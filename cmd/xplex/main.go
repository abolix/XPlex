// Command mp is the unified entrypoint for the multipath proxy.
//
//	mp client -config mp.config.json
//	  Spawns one xray per share link in xrays.txt, opens a long-lived
//	  multipath tunnel pool to the remote mp server, and exposes a
//	  local SOCKS5 endpoint that multiplexes every accepted client
//	  across all live tunnels.
//
//	mp server -listen 7000
//	  Accepts incoming tunnels, demuxes by session ID, dials each
//	  session's destination, and pumps bytes.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"xplex/internal/config"
	"xplex/internal/links"
	"xplex/internal/monitor"
	"xplex/internal/mpadapt"
	"xplex/internal/mpconfig"
	"xplex/internal/mpcrypto"
	"xplex/internal/mpfront"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
	"xplex/internal/mpserver"
	"xplex/internal/runner"
	"xplex/internal/socks5"
	"xplex/internal/stats"
)

const statsWindow = 10

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]
	args := os.Args[2:]
	var err error
	switch mode {
	case "client":
		err = runClient(args)
	case "server":
		err = runServer(args)
	case "gen-key":
		err = runGenKey()
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n\n", mode)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  mp client [-config PATH] [-listen PORT] [-server HOST:PORT] [-xrays PATH] [-psk HEX]")
	fmt.Fprintln(os.Stderr, "  mp server [-config PATH] [-listen PORT] [-psk HEX]")
	fmt.Fprintln(os.Stderr, "  mp gen-key")
}

// runGenKey prints a fresh hex-encoded 32-byte pre-shared key.
func runGenKey() error {
	var key [32]byte
	if _, err := cryptorand.Read(key[:]); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	fmt.Println(hex.EncodeToString(key[:]))
	return nil
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var (
		configPath string
		listen     string
		server     string
		xrayLinks  string
		psk        string
	)
	fs.StringVar(&configPath, "config", "", "path to JSON config (optional)")
	fs.StringVar(&listen, "listen", "", "local SOCKS5 listen port or host:port (default 2080 -> 127.0.0.1:2080)")
	fs.StringVar(&server, "server", "", "remote mp server address (host:port)")
	fs.StringVar(&xrayLinks, "xrays", "", "path to xrays.txt (default ./xrays.txt)")
	fs.StringVar(&psk, "psk", "", "hex-encoded 32-byte pre-shared key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	file, err := mpconfig.Load(configPath)
	if err != nil {
		return err
	}
	cfg, err := mpconfig.ResolveClient(file.Client, mpconfig.ClientOverrides{
		Listen:    listen,
		Server:    server,
		XrayLinks: xrayLinks,
		PSK:       psk,
	})
	if err != nil {
		return err
	}

	codec, err := mpcrypto.New(cfg.PSK)
	if err != nil {
		return fmt.Errorf("psk: %w", err)
	}

	xrayBin := cfg.XrayBin
	if xrayBin == "" {
		exe := "xray"
		if runtime.GOOS == "windows" {
			exe = "xray.exe"
		}
		xrayBin = filepath.Join("xray-core", exe)
	}
	if !filepath.IsAbs(xrayBin) {
		abs, err := filepath.Abs(xrayBin)
		if err != nil {
			return err
		}
		xrayBin = abs
	}
	xrayDir := filepath.Dir(xrayBin)
	if _, err := os.Stat(xrayBin); err != nil {
		return fmt.Errorf("xray binary not found at %s", xrayBin)
	}

	allLinks, err := links.Read(cfg.XrayLinks)
	if err != nil {
		return fmt.Errorf("read links: %w", err)
	}
	if len(allLinks) == 0 {
		return fmt.Errorf("%s contains no links", cfg.XrayLinks)
	}
	if err := os.MkdirAll(cfg.ConfigsDir, 0o755); err != nil {
		return err
	}
	configsDirAbs, err := filepath.Abs(cfg.ConfigsDir)
	if err != nil {
		return err
	}

	running, err := startXrays(allLinks, configsDirAbs, xrayBin, xrayDir, cfg.XrayBasePort)
	if err != nil {
		runner.Stop(running)
		return err
	}
	defer runner.Stop(running)
	waitForReady(running, 5*time.Second)

	mpHost, mpPort, err := splitHostPort(cfg.Server)
	if err != nil {
		return fmt.Errorf("server addr: %w", err)
	}

	ctx, cancel := withSignals(context.Background())
	defer cancel()

	tracker := stats.NewTracker(statsWindow)

	// Build dialers: one per xray. Each dialer SOCKS5-CONNECTs to the
	// mp-server through its xray. The pool keeps these alive forever.
	dialers := make([]mppool.DialFunc, 0, len(running))
	names := make([]string, 0, len(running))
	for _, inst := range running {
		inst := inst
		xrayAddr := fmt.Sprintf("127.0.0.1:%d", inst.Port)
		dialers = append(dialers, func(ctx context.Context) (net.Conn, error) {
			t := 10 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				t = time.Until(dl)
			}
			return socks5.Dial(xrayAddr, mpHost, mpPort, t)
		})
		names = append(names, strconv.Itoa(inst.Port))
	}

	pool := mppool.New(ctx, mppool.Config{Dialers: dialers, Names: names, Codec: codec})
	defer pool.Close()

	hub := mphub.New(ctx, pool, nil) // client doesn't accept new sessions
	defer hub.Close()

	// Adaptive duplication controller: every few seconds, look at
	// per-tunnel win counts and shift slow tunnels into Shadow state
	// so we stop wasting outbound bandwidth on them. Slow tunnels
	// stay open and keep reading; if conditions change they get
	// promoted back to Active automatically.
	go mpadapt.Run(ctx, hub, mpadapt.DefaultConfig())

	front := mpfront.New(hub, mpfront.Config{
		ListenAddr: cfg.Listen,
	})

	monDone := make(chan struct{})
	go func() {
		monitor.Run(ctx, running, tracker, cfg.ProbeInterval, cfg.ProbeTimeout)
		close(monDone)
	}()

	frontDone := make(chan error, 1)
	go func() { frontDone <- front.Run(ctx) }()

	procDone := make(chan struct{})
	// Supervise the xray process: restart automatically on crash.
	go func() {
		defer close(procDone)
		const (
			minRestartDelay = 2 * time.Second
			maxRestartDelay = 30 * time.Second
		)
		delay := minRestartDelay
		for {
			_ = running[0].Cmd.Wait()
			if ctx.Err() != nil {
				return // shutting down, don't restart
			}
			fmt.Printf("xray exited unexpectedly, restarting in %v...\n", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			inst, err := runner.Start(xrayBin, xrayDir,
				filepath.Join(configsDirAbs, "xray_multi.json"),
				cfg.XrayBasePort, "multi")
			if err != nil {
				fmt.Printf("xray restart failed: %v (retry in %v)\n", err, delay)
				delay *= 2
				if delay > maxRestartDelay {
					delay = maxRestartDelay
				}
				continue
			}
			fmt.Printf("xray restarted (pid %d)\n", inst.Cmd.Process.Pid)
			// Update all pseudo-instances to point at the new Cmd.
			for i := range running {
				running[i].Cmd = inst.Cmd
			}
			delay = minRestartDelay // reset backoff on successful start
			waitForReady(running, 5*time.Second)
		}
	}()

	select {
	case err := <-frontDone:
		if err != nil {
			fmt.Printf("frontend error: %v\n", err)
		}
	case <-ctx.Done():
	}
	cancel()
	<-procDone
	<-monDone
	return nil
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var (
		configPath string
		listen     string
		psk        string
	)
	fs.StringVar(&configPath, "config", "", "path to JSON config (optional)")
	fs.StringVar(&listen, "listen", "", "tunnel listen port or host:port (default 7000 -> 0.0.0.0:7000)")
	fs.StringVar(&psk, "psk", "", "hex-encoded 32-byte pre-shared key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	file, err := mpconfig.Load(configPath)
	if err != nil {
		return err
	}
	cfg, err := mpconfig.ResolveServer(file.Server, listen, psk, 0)
	if err != nil {
		return err
	}

	codec, err := mpcrypto.New(cfg.PSK)
	if err != nil {
		return fmt.Errorf("psk: %w", err)
	}

	ctx, cancel := withSignals(context.Background())
	defer cancel()

	srv := mpserver.New(mpserver.Config{ListenAddr: cfg.Listen, Codec: codec})
	return srv.Run(ctx)
}

func startXrays(allLinks []string, configsDir, xrayBin, xrayDir string, basePort int) ([]*runner.Instance, error) {
	// Single-process mode: generate one xray config with all inbounds/outbounds.
	entries := make([]config.MultiEntry, len(allLinks))
	for i, link := range allLinks {
		entries[i] = config.MultiEntry{Link: link, Port: basePort + i}
	}
	multiCfg, err := config.BuildMulti(entries)
	if err != nil {
		return nil, fmt.Errorf("build multi config: %w", err)
	}
	cfgPath := filepath.Join(configsDir, "xray_multi.json")
	if err := config.WriteMultiJSON(multiCfg, cfgPath); err != nil {
		return nil, fmt.Errorf("write multi config: %w", err)
	}

	inst, err := runner.Start(xrayBin, xrayDir, cfgPath, basePort, "multi")
	if err != nil {
		return nil, err
	}
	fmt.Printf("started xray (single process, %d outbounds) on ports %d-%d (pid %d)\n",
		len(allLinks), basePort, basePort+len(allLinks)-1, inst.Cmd.Process.Pid)

	// Return one Instance per port so the rest of the code (dialers, monitor)
	// still works unchanged.
	out := make([]*runner.Instance, len(allLinks))
	for i, link := range allLinks {
		port := basePort + i
		out[i] = &runner.Instance{
			Port: port,
			Link: link,
			Cmd:  inst.Cmd, // shared process handle
		}
	}
	return out, nil
}

func waitForReady(running []*runner.Instance, timeout time.Duration) {
	var wg sync.WaitGroup
	for _, inst := range running {
		wg.Add(1)
		go func(inst *runner.Instance) {
			defer wg.Done()
			if err := runner.WaitReady(inst, timeout); err != nil {
				fmt.Printf("warn: %v\n", err)
			}
		}(inst)
	}
	wg.Wait()
}

func withSignals(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nshutting down...")
		cancel()
	}()
	return ctx, cancel
}

func splitHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	if p < 0 || p > 0xffff {
		return "", 0, fmt.Errorf("port out of range")
	}
	return host, uint16(p), nil
}

