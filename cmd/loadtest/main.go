// Command loadtest drives concurrent HTTP requests through a SOCKS5
// proxy and reports latency percentiles + error counts.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"xplex/internal/socks5"
)

func main() {
	var (
		proxyAddr  string
		targetURL  string
		total      int
		concurrent int
		timeout    time.Duration
	)
	flag.StringVar(&proxyAddr, "proxy", "127.0.0.1:2080", "SOCKS5 proxy host:port")
	flag.StringVar(&targetURL, "url", "http://www.gstatic.com/generate_204", "URL to fetch")
	flag.IntVar(&total, "n", 100, "total requests")
	flag.IntVar(&concurrent, "c", 8, "concurrent workers")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "per-request timeout")
	flag.Parse()

	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad url:", err)
		os.Exit(2)
	}
	host := u.Hostname()
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		_, _ = fmt.Sscanf(u.Port(), "%d", &port)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5.Dial(proxyAddr, host, port, timeout)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	fmt.Printf("loadtest: proxy=%s url=%s n=%d c=%d\n", proxyAddr, targetURL, total, concurrent)

	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	latencies := make([]time.Duration, 0, total)
	var latMu sync.Mutex
	var failures atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < concurrent; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				resp, err := client.Get(targetURL)
				if err != nil {
					failures.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				lat := time.Since(t0)
				if resp.StatusCode >= 400 {
					failures.Add(1)
					continue
				}
				latMu.Lock()
				latencies = append(latencies, lat)
				latMu.Unlock()
			}
		}()
	}
	wg.Wait()
	totalDur := time.Since(start)
	report(latencies, int(failures.Load()), total, totalDur)
}

func report(latencies []time.Duration, failures, total int, totalDur time.Duration) {
	if len(latencies) == 0 {
		fmt.Printf("\n%d/%d failed; no successful samples\n", failures, total)
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(q float64) time.Duration {
		idx := int(q * float64(len(latencies)-1))
		return latencies[idx]
	}
	var sum time.Duration
	for _, d := range latencies {
		sum += d
	}
	mean := sum / time.Duration(len(latencies))
	fmt.Printf("\nresults:\n")
	fmt.Printf("  total:   %d requests in %v\n", total, totalDur.Round(time.Millisecond))
	fmt.Printf("  ok:      %d\n", len(latencies))
	fmt.Printf("  fail:    %d\n", failures)
	fmt.Printf("  rps:     %.1f\n", float64(total)/totalDur.Seconds())
	fmt.Printf("  latency: min=%v p50=%v p90=%v p95=%v p99=%v max=%v mean=%v\n",
		latencies[0].Round(time.Millisecond),
		p(0.50).Round(time.Millisecond),
		p(0.90).Round(time.Millisecond),
		p(0.95).Round(time.Millisecond),
		p(0.99).Round(time.Millisecond),
		latencies[len(latencies)-1].Round(time.Millisecond),
		mean.Round(time.Millisecond),
	)
}

