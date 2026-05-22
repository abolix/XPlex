package mpconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xplex/internal/mpconfig"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoad_EmptyPath(t *testing.T) {
	f, err := mpconfig.Load("")
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if f.Client != nil || f.Server != nil {
		t.Errorf("expected empty File, got %+v", f)
	}
}

func TestLoad_BothBlocks(t *testing.T) {
	p := writeTemp(t, `{
		"client": {"listen": "2080", "server": "host:7000", "xrayLinks": "xrays.txt"},
		"server": {"listen": "7000"}
	}`)
	f, err := mpconfig.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Client == nil || f.Server == nil {
		t.Fatal("expected both blocks parsed")
	}
}

func TestLoad_BadJSON(t *testing.T) {
	p := writeTemp(t, "{not json")
	_, err := mpconfig.Load(p)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := mpconfig.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNormalizeListen_BarePort(t *testing.T) {
	got, err := mpconfig.NormalizeListen("3333", "127.0.0.1")
	if err != nil {
		t.Fatalf("NormalizeListen: %v", err)
	}
	if got != "127.0.0.1:3333" {
		t.Errorf("got %q, want 127.0.0.1:3333", got)
	}
}

func TestNormalizeListen_HostPort(t *testing.T) {
	got, err := mpconfig.NormalizeListen("0.0.0.0:7000", "127.0.0.1")
	if err != nil {
		t.Fatalf("NormalizeListen: %v", err)
	}
	if got != "0.0.0.0:7000" {
		t.Errorf("expected unchanged, got %q", got)
	}
}

func TestNormalizeListen_NotANumber(t *testing.T) {
	_, err := mpconfig.NormalizeListen("abc", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error for non-numeric bare port")
	}
}

func TestNormalizeListen_Empty(t *testing.T) {
	got, _ := mpconfig.NormalizeListen("", "127.0.0.1")
	if got != "" {
		t.Errorf("empty input should stay empty, got %q", got)
	}
}

func TestResolveClient_FileOnly(t *testing.T) {
	cfg, err := mpconfig.ResolveClient(&mpconfig.ClientFile{
		Listen:           "9000",
		Server:           "vps:7000",
		XrayLinks:        "links.txt",
		XrayBasePort:     2000,
		HandshakeTimeout: "5s",
		ProbeInterval:    "20s",
		ProbeTimeout:     "3s",
		PSK:              "0000000000000000000000000000000000000000000000000000000000000000",
	}, mpconfig.ClientOverrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("listen normalization failed: %v", cfg.Listen)
	}
	if cfg.Server != "vps:7000" {
		t.Errorf("server: %v", cfg.Server)
	}
	if cfg.XrayLinks != "links.txt" {
		t.Errorf("xrayLinks: %v", cfg.XrayLinks)
	}
	if cfg.XrayBasePort != 2000 {
		t.Errorf("xrayBasePort: %d", cfg.XrayBasePort)
	}
	if cfg.HandshakeTimeout != 5*time.Second {
		t.Errorf("handshakeTimeout: %v", cfg.HandshakeTimeout)
	}
	if cfg.ProbeInterval != 20*time.Second {
		t.Errorf("probeInterval: %v", cfg.ProbeInterval)
	}
	if cfg.ProbeTimeout != 3*time.Second {
		t.Errorf("probeTimeout: %v", cfg.ProbeTimeout)
	}
}

func TestResolveClient_FlagsOverrideFile(t *testing.T) {
	cfg, err := mpconfig.ResolveClient(&mpconfig.ClientFile{
		Listen:    "9000",
		Server:    "fileserver:7000",
		XrayLinks: "fileLinks.txt",
		PSK:       "0000000000000000000000000000000000000000000000000000000000000000",
	}, mpconfig.ClientOverrides{
		Listen:           "1234",
		Server:           "flagserver:7000",
		XrayLinks:        "flagLinks.txt",
		HandshakeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1234" {
		t.Errorf("flag listen not honored: %v", cfg.Listen)
	}
	if cfg.Server != "flagserver:7000" {
		t.Errorf("flag server not honored: %v", cfg.Server)
	}
	if cfg.XrayLinks != "flagLinks.txt" {
		t.Errorf("flag xrayLinks not honored: %v", cfg.XrayLinks)
	}
	if cfg.HandshakeTimeout != 3*time.Second {
		t.Errorf("flag timeout not honored: %v", cfg.HandshakeTimeout)
	}
}

func TestResolveClient_DefaultsApplied(t *testing.T) {
	cfg, err := mpconfig.ResolveClient(nil, mpconfig.ClientOverrides{
		Server: "vps:7000",
		PSK:    "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Listen != "127.0.0.1:2080" {
		t.Errorf("default listen: %v", cfg.Listen)
	}
	if cfg.XrayLinks != "xrays.txt" {
		t.Errorf("default xrayLinks: %v", cfg.XrayLinks)
	}
	if cfg.XrayBasePort != 1080 {
		t.Errorf("default xrayBasePort: %d", cfg.XrayBasePort)
	}
	if cfg.ConfigsDir != "configs" {
		t.Errorf("default configsDir: %v", cfg.ConfigsDir)
	}
	if cfg.HandshakeTimeout != 3*time.Second {
		t.Errorf("default handshakeTimeout: %v", cfg.HandshakeTimeout)
	}
	if cfg.ProbeInterval != 30*time.Second {
		t.Errorf("default probeInterval: %v", cfg.ProbeInterval)
	}
	if cfg.ProbeTimeout != 10*time.Second {
		t.Errorf("default probeTimeout: %v", cfg.ProbeTimeout)
	}
}

func TestResolveClient_RequiresServer(t *testing.T) {
	_, err := mpconfig.ResolveClient(nil, mpconfig.ClientOverrides{})
	if err == nil || !strings.Contains(err.Error(), "server") {
		t.Fatalf("expected server-required error, got %v", err)
	}
}

func TestResolveClient_BadTimeoutString(t *testing.T) {
	_, err := mpconfig.ResolveClient(&mpconfig.ClientFile{
		Server:           "vps:7000",
		HandshakeTimeout: "not a duration",
	}, mpconfig.ClientOverrides{})
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
}

func TestResolveServer_FileOnly(t *testing.T) {
	cfg, err := mpconfig.ResolveServer(&mpconfig.ServerFile{
		Listen:           "9000",
		HandshakeTimeout: "15s",
	}, "", "0000000000000000000000000000000000000000000000000000000000000000", 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9000" {
		t.Errorf("listen not normalized: %v", cfg.Listen)
	}
	if cfg.HandshakeTimeout != 15*time.Second {
		t.Errorf("timeout: %v", cfg.HandshakeTimeout)
	}
}

func TestResolveServer_FlagsOverrideFile(t *testing.T) {
	cfg, err := mpconfig.ResolveServer(&mpconfig.ServerFile{
		Listen: "9000",
	}, "7777", "0000000000000000000000000000000000000000000000000000000000000000", 2*time.Second)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.Listen != "0.0.0.0:7777" || cfg.HandshakeTimeout != 2*time.Second {
		t.Errorf("flags not honored: %+v", cfg)
	}
}

func TestResolveServer_DefaultListen(t *testing.T) {
	cfg, _ := mpconfig.ResolveServer(nil, "", "0000000000000000000000000000000000000000000000000000000000000000", 0)
	if cfg.Listen != "0.0.0.0:7000" {
		t.Errorf("default listen wrong: %v", cfg.Listen)
	}
}

