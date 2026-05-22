package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// asMap is a helper for poking at the generated JSON in a typed way.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T (%v)", v, v)
	}
	return m
}

func TestBuild_Trojan_WS_TLS(t *testing.T) {
	link := "trojan://secretpw@example.com:40443" +
		"?security=tls&sni=cdn.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1" +
		"&allowInsecure=0&type=ws&host=cdn.example.com&path=%2Fws#tag"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	in := cfg.Inbounds[0]
	if in.Port != 1080 || in.Protocol != "socks" || in.Listen != "127.0.0.1" {
		t.Errorf("inbound mismatch: %+v", in)
	}

	if len(cfg.Outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(cfg.Outbounds))
	}
	proxy := cfg.Outbounds[0]
	if proxy.Protocol != "trojan" || proxy.Tag != "proxy" {
		t.Errorf("outbound mismatch: %+v", proxy)
	}
	servers := proxy.Settings["servers"].([]map[string]any)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s["address"] != "example.com" {
		t.Errorf("address: got %v, want example.com", s["address"])
	}
	if s["port"] != 40443 {
		t.Errorf("port: got %v, want 40443", s["port"])
	}
	if s["password"] != "secretpw" {
		t.Errorf("password: got %v, want secretpw", s["password"])
	}

	stream := proxy.StreamSettings
	if stream["network"] != "ws" {
		t.Errorf("network: got %v, want ws", stream["network"])
	}
	if stream["security"] != "tls" {
		t.Errorf("security: got %v, want tls", stream["security"])
	}

	tls := asMap(t, stream["tlsSettings"])
	if tls["serverName"] != "cdn.example.com" {
		t.Errorf("sni: %v", tls["serverName"])
	}
	if tls["fingerprint"] != "chrome" {
		t.Errorf("fp: %v", tls["fingerprint"])
	}
	alpn, ok := tls["alpn"].([]string)
	if !ok || len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("alpn: %v", tls["alpn"])
	}
	if tls["allowInsecure"] != false {
		t.Errorf("allowInsecure: got %v, want false", tls["allowInsecure"])
	}

	ws := asMap(t, stream["wsSettings"])
	if ws["path"] != "/ws" {
		t.Errorf("ws path: %v", ws["path"])
	}
	headers := asMap(t, ws["headers"])
	if headers["Host"] != "cdn.example.com" {
		t.Errorf("ws Host header: %v", headers["Host"])
	}

	// Direct outbound is always present last.
	if cfg.Outbounds[1].Protocol != "freedom" || cfg.Outbounds[1].Tag != "direct" {
		t.Errorf("expected freedom/direct as second outbound, got %+v", cfg.Outbounds[1])
	}
}

func TestBuild_Vless_TCP_NoSecurity(t *testing.T) {
	link := "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443"
	cfg, err := Build(link, 1081)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	proxy := cfg.Outbounds[0]
	if proxy.Protocol != "vless" {
		t.Errorf("protocol: got %s, want vless", proxy.Protocol)
	}
	vnext := proxy.Settings["vnext"].([]map[string]any)
	if len(vnext) != 1 {
		t.Fatalf("expected 1 vnext, got %d", len(vnext))
	}
	users := vnext[0]["users"].([]map[string]any)
	u := users[0]
	if u["id"] != "6202b230-417c-4d8e-b624-0f71afa9c75d" {
		t.Errorf("id: %v", u["id"])
	}
	// Encryption defaults to "none" when not provided.
	if u["encryption"] != "none" {
		t.Errorf("encryption: got %v, want none", u["encryption"])
	}
	stream := proxy.StreamSettings
	// Defaults for absent type and security.
	if stream["network"] != "tcp" {
		t.Errorf("network default: %v", stream["network"])
	}
	if stream["security"] != "none" {
		t.Errorf("security default: %v", stream["security"])
	}
	if _, ok := stream["tlsSettings"]; ok {
		t.Errorf("tlsSettings should be absent when security=none")
	}
}

func TestBuild_Vless_PreservesFlow(t *testing.T) {
	link := "vless://uuid@example.com:443?flow=xtls-rprx-vision&security=tls&sni=x"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	user := cfg.Outbounds[0].Settings["vnext"].([]map[string]any)[0]["users"].([]map[string]any)[0]
	if user["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow: got %v, want xtls-rprx-vision", user["flow"])
	}
}

func TestBuild_AllowInsecure_FromInsecureFallback(t *testing.T) {
	// `allowInsecure` absent, but `insecure=1` is present.
	link := "trojan://pw@example.com:443?security=tls&sni=x&insecure=1"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tls := asMap(t, cfg.Outbounds[0].StreamSettings["tlsSettings"])
	if tls["allowInsecure"] != true {
		t.Errorf("allowInsecure should be true via insecure=1, got %v", tls["allowInsecure"])
	}
}

func TestBuild_WS_DefaultPath(t *testing.T) {
	link := "trojan://pw@example.com:443?type=ws"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ws := asMap(t, cfg.Outbounds[0].StreamSettings["wsSettings"])
	if ws["path"] != "/" {
		t.Errorf("default ws path: got %v, want /", ws["path"])
	}
	if _, hasHeaders := ws["headers"]; hasHeaders {
		t.Errorf("headers should be absent when host is not provided")
	}
}

func TestBuild_GRPC(t *testing.T) {
	link := "vless://uuid@example.com:443?type=grpc&serviceName=mygrpc&security=tls&sni=x"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	stream := cfg.Outbounds[0].StreamSettings
	if stream["network"] != "grpc" {
		t.Errorf("network: %v", stream["network"])
	}
	grpc := asMap(t, stream["grpcSettings"])
	if grpc["serviceName"] != "mygrpc" {
		t.Errorf("serviceName: %v", grpc["serviceName"])
	}
}

func TestBuild_TCPWithHTTPHeader(t *testing.T) {
	link := "vless://uuid@example.com:80?type=tcp&headerType=http"
	cfg, err := Build(link, 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tcp := asMap(t, cfg.Outbounds[0].StreamSettings["tcpSettings"])
	header := asMap(t, tcp["header"])
	if header["type"] != "http" {
		t.Errorf("tcp header type: %v", header["type"])
	}
}

func TestBuild_UnsupportedScheme(t *testing.T) {
	_, err := Build("vmess://blob@example.com:443", 1080)
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestBuild_InvalidPort(t *testing.T) {
	_, err := Build("trojan://pw@example.com", 1080)
	if err == nil {
		t.Fatal("expected error when port is missing")
	}
}

func TestBuild_TrimsWhitespace(t *testing.T) {
	link := "   trojan://pw@example.com:443   "
	if _, err := Build(link, 1080); err != nil {
		t.Fatalf("Build should trim whitespace: %v", err)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	cfg, err := Build("trojan://pw@example.com:443?type=ws&path=%2Fp", 1080)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "x.json")
	if err := WriteJSON(cfg, out); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// Parse the file back and spot-check a few fields. Don't compare to
	// the original struct because map[string]any equality is finicky.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	inbounds := parsed["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(inbounds))
	}
	if inbounds[0].(map[string]any)["port"].(float64) != 1080 {
		t.Errorf("inbound port mismatch")
	}
}

