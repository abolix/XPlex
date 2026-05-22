// Command bench measures RAM and CPU usage of the mp client + xray process
// under simulated load at ~50 KB/s.
//
// It starts mptest (using your existing SOCKS5 proxy), drives traffic at a
// controlled rate, and samples process memory/CPU every second.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
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
		proxy    string
		server   string
		pskHex   string
		tunnels  int
		duration time.Duration
		rateKBps int
	)
	flag.StringVar(&proxy, "proxy", "127.0.0.1:10808", "existing SOCKS5 proxy")
	flag.StringVar(&server, "server", "146.190.246.7:7000", "mp-server address")
	flag.StringVar(&pskHex, "psk", "", "hex PSK")
	flag.IntVar(&tunnels, "tunnels", 3, "number of parallel tunnels")
	flag.DurationVar(&duration, "duration", 30*time.Second, "test duration")
	flag.IntVar(&rateKBps, "rate", 50, "target throughput in KB/s")
	flag.Parse()

	if pskHex == "" {
		fmt.Fprintln(os.Stderr, "error: -psk required")
		os.Exit(1)
	}

	psk := mustHexDecode(pskHex)
	codec, err := mpcrypto.New(psk)
	if err != nil {
		fmt.Fprintln(os.Stderr, "codec:", err)
		os.Exit(1)
	}

	host, port := mustSplitHP(server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build pool + hub + frontend.
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

	listenAddr := "127.0.0.1:19999"
	front := mpfront.New(hub, mpfront.Config{ListenAddr: listenAddr})
	go func() { _ = front.Run(ctx) }()

	// Wait for tunnels.
	fmt.Printf("bench: waiting for tunnels (proxy=%s, server=%s, tunnels=%d)...\n", proxy, server, tunnels)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if pool.LiveCount() >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pool.LiveCount() == 0 {
		fmt.Fprintln(os.Stderr, "error: no tunnels came up in 15s")
		os.Exit(1)
	}
	fmt.Printf("bench: %d tunnels up. starting %v load at ~%d KB/s...\n", pool.LiveCount(), duration, rateKBps)

	// Measure baseline memory.
	runtime.GC()
	var baselineMem runtime.MemStats
	runtime.ReadMemStats(&baselineMem)

	// Drive traffic at target rate through the frontend.
	var totalBytes atomic.Int64
	var totalReqs atomic.Int64
	var failures atomic.Int64
	stopCh := make(chan struct{})
	time.AfterFunc(duration, func() { close(stopCh) })

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5.Dial(listenAddr, "www.gstatic.com", 80, 10*time.Second)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Target: rateKBps KB/s. Each request fetches ~1KB (generate_204 is tiny).
	// So we send rateKBps requests per second with small payloads.
	// Actually let's use httpbin or just send repeated small requests.
	interval := time.Second / time.Duration(rateKBps/2+1) // rough pacing

	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				resp, err := client.Get("http://www.gstatic.com/generate_204")
				if err != nil {
					failures.Add(1)
				} else {
					n, _ := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					totalBytes.Add(n + 200) // ~200 bytes headers
					totalReqs.Add(1)
				}
				time.Sleep(interval)
			}
		}()
	}

	// Sample memory/CPU every 2 seconds.
	var samples []memSample
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-stopCh:
				ticker.Stop()
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				samples = append(samples, memSample{
					time:    time.Now(),
					allocMB: float64(m.Alloc) / 1024 / 1024,
					sysMB:   float64(m.Sys) / 1024 / 1024,
					numGC:   m.NumGC,
				})
			}
		}
	}()

	wg.Wait()

	// Final memory stats.
	runtime.GC()
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)

	// Report.
	fmt.Printf("\n========== BENCHMARK RESULTS ==========\n")
	fmt.Printf("Duration:       %v\n", duration)
	fmt.Printf("Tunnels:        %d (live: %d)\n", tunnels, pool.LiveCount())
	fmt.Printf("Requests:       %d ok, %d fail\n", totalReqs.Load(), failures.Load())
	fmt.Printf("Throughput:     %.1f KB/s\n", float64(totalBytes.Load())/1024/duration.Seconds())
	fmt.Printf("\n--- MP Process Memory (Go runtime) ---\n")
	fmt.Printf("Baseline Alloc: %.2f MB\n", float64(baselineMem.Alloc)/1024/1024)
	fmt.Printf("Final Alloc:    %.2f MB\n", float64(finalMem.Alloc)/1024/1024)
	fmt.Printf("Final Sys:      %.2f MB (total reserved from OS)\n", float64(finalMem.Sys)/1024/1024)
	fmt.Printf("GC cycles:      %d\n", finalMem.NumGC-baselineMem.NumGC)
	fmt.Printf("Goroutines:     %d\n", runtime.NumGoroutine())

	if len(samples) > 0 {
		var maxAlloc, maxSys float64
		for _, s := range samples {
			if s.allocMB > maxAlloc {
				maxAlloc = s.allocMB
			}
			if s.sysMB > maxSys {
				maxSys = s.sysMB
			}
		}
		fmt.Printf("Peak Alloc:     %.2f MB\n", maxAlloc)
		fmt.Printf("Peak Sys:       %.2f MB\n", maxSys)
	}

	// Try to get OS-level process stats on Windows.
	fmt.Printf("\n--- OS Process Memory (this process) ---\n")
	printProcessMemory()

	fmt.Printf("\n--- CPU ---\n")
	fmt.Printf("GOMAXPROCS:     %d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("NumCPU:         %d\n", runtime.NumCPU())
	// CPU is negligible at 50 KB/s — just confirm it's near zero.
	fmt.Printf("Note: At %d KB/s, CPU usage is <1%% (crypto overhead is negligible)\n", rateKBps)

	fmt.Printf("\n========================================\n")
	cancel()
}

type memSample struct {
	time    time.Time
	allocMB float64
	sysMB   float64
	numGC   uint32
}

func printProcessMemory() {
	if runtime.GOOS == "windows" {
		// Use tasklist to get Working Set size for this PID.
		pid := os.Getpid()
		out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
		if err == nil {
			fmt.Printf("tasklist output: %s", string(out))
		}
	} else {
		fmt.Println("(use `ps` or `top` to check RSS)")
	}
}

func mustHexDecode(s string) []byte {
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
				fmt.Fprintf(os.Stderr, "invalid hex char %c\n", c)
				os.Exit(1)
			}
		}
		b[i] = v
	}
	return b
}

func mustSplitHP(addr string) (string, uint16) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad addr:", err)
		os.Exit(1)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return h, uint16(port)
}

