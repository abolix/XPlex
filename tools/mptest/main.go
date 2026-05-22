// Command mptest starts a minimal mp client using an existing SOCKS5
// proxy (e.g. v2rayN on 10808) as the tunnel path, without spawning xrays.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xplex/internal/mpadapt"
	"xplex/internal/mpcrypto"
	"xplex/internal/mpfront"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
	"xplex/internal/socks5"
)

func main() {
	var (
		listen  string
		server  string
		proxy   string
		pskHex  string
		tunnels int
	)
	flag.StringVar(&listen, "listen", "127.0.0.1:2080", "local SOCKS5 frontend")
	flag.StringVar(&server, "server", "146.190.246.7:7000", "mp-server address")
	flag.StringVar(&proxy, "proxy", "127.0.0.1:10808", "existing SOCKS5 proxy to tunnel through")
	flag.StringVar(&pskHex, "psk", "", "hex PSK")
	flag.IntVar(&tunnels, "tunnels", 3, "number of parallel tunnels")
	flag.Parse()

	if pskHex == "" {
		fmt.Fprintln(os.Stderr, "error: -psk required")
		os.Exit(1)
	}

	psk, err := hexDecode(pskHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad psk:", err)
		os.Exit(1)
	}
	codec, err := mpcrypto.New(psk)
	if err != nil {
		fmt.Fprintln(os.Stderr, "codec:", err)
		os.Exit(1)
	}

	host, port, err := splitHP(server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad server:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	dialers := make([]mppool.DialFunc, tunnels)
	names := make([]string, tunnels)
	for i := range dialers {
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			t := 10 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				t = time.Until(dl)
			}
			return socks5.Dial(proxy, host, port, t)
		}
		names[i] = fmt.Sprintf("t%d", i)
	}

	pool := mppool.New(ctx, mppool.Config{Dialers: dialers, Names: names, Codec: codec})
	defer pool.Close()

	hub := mphub.New(ctx, pool, nil)
	defer hub.Close()

	go mpadapt.Run(ctx, hub, mpadapt.DefaultConfig())

	front := mpfront.New(hub, mpfront.Config{ListenAddr: listen})
	fmt.Printf("mptest: frontend=%s server=%s proxy=%s tunnels=%d\n", listen, server, proxy, tunnels)
	if err := front.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	cancel()
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				v = v*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = v*16 + (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex char %c", c)
			}
		}
		b[i] = v
	}
	return b, nil
}

func splitHP(addr string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return h, uint16(port), nil
}

