// Package runner spawns and supervises xray.exe child processes.
package runner

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Instance describes one running xray child.
type Instance struct {
	Port int
	Link string
	Cmd  *exec.Cmd
}

// Start launches xray with the given config file and tags stdout/stderr with
// a port-prefixed line writer.
func Start(xrayBin, xrayDir, configPath string, port int, link string) (*Instance, error) {
	cmd := exec.Command(xrayBin, "-c", configPath)
	cmd.Dir = xrayDir
	prefix := fmt.Sprintf("[%d] ", port)
	cmd.Stdout = newPrefixWriter(prefix, os.Stdout)
	cmd.Stderr = newPrefixWriter(prefix, os.Stderr)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start xray on %d: %w", port, err)
	}
	return &Instance{Port: port, Link: link, Cmd: cmd}, nil
}

// Stop kills all running instances. Errors are ignored — best effort.
func Stop(instances []*Instance) {
	for _, inst := range instances {
		if inst == nil || inst.Cmd == nil || inst.Cmd.Process == nil {
			continue
		}
		_ = inst.Cmd.Process.Kill()
	}
}

// WaitReady polls the instance's SOCKS5 port until a TCP connection
// succeeds or the timeout elapses. Returns nil once the port is
// accepting connections.
func WaitReady(inst *Instance, timeout time.Duration) error {
	addr := "127.0.0.1:" + strconv.Itoa(inst.Port)
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("xray on :%d not ready after %s: %w",
				inst.Port, timeout, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// prefixWriter prepends a fixed string to each Write call so logs from
// multiple xray processes stay distinguishable in a single terminal.
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func newPrefixWriter(prefix string, w io.Writer) *prefixWriter {
	return &prefixWriter{prefix: prefix, w: w}
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	if _, err := io.WriteString(p.w, p.prefix); err != nil {
		return 0, err
	}
	if _, err := p.w.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

