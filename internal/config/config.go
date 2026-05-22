// Package config builds Xray JSON configs from share links.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// XrayConfig is the minimal subset of Xray's JSON config we generate.
type XrayConfig struct {
	Log       map[string]string `json:"log"`
	Inbounds  []Inbound         `json:"inbounds"`
	Outbounds []Outbound        `json:"outbounds"`
}

// Inbound represents a single Xray inbound entry.
type Inbound struct {
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Tag      string         `json:"tag,omitempty"`
	Settings map[string]any `json:"settings"`
	Sniffing map[string]any `json:"sniffing,omitempty"`
}

// Outbound represents a single Xray outbound entry.
type Outbound struct {
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings,omitempty"`
	Tag            string         `json:"tag,omitempty"`
}

// Build returns a complete Xray config: SOCKS5 inbound on the given port
// + a proxy outbound built from the supplied share link.
func Build(link string, socksPort int) (XrayConfig, error) {
	out, err := parseShareLink(link)
	if err != nil {
		return XrayConfig{}, err
	}
	return XrayConfig{
		Log: map[string]string{"loglevel": "warning"},
		Inbounds: []Inbound{
			{
				Listen:   "127.0.0.1",
				Port:     socksPort,
				Protocol: "socks",
				Settings: map[string]any{
					"udp":  true,
					"auth": "noauth",
				},
				Sniffing: map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		Outbounds: []Outbound{
			out,
			{Protocol: "freedom", Settings: map[string]any{}, Tag: "direct"},
		},
	}, nil
}

// MultiEntry pairs one share link with its assigned SOCKS5 port.
type MultiEntry struct {
	Link string
	Port int
}

// BuildMulti generates a single Xray config with N inbounds (one per link)
// and N+1 outbounds (one proxy per link + freedom fallback). Routing rules
// direct each inbound tag to its matching outbound tag.
//
// This lets you run ONE xray process instead of N, saving ~30 MB RAM per
// eliminated process.
func BuildMulti(entries []MultiEntry) (XrayMultiConfig, error) {
	cfg := XrayMultiConfig{
		Log:     map[string]string{"loglevel": "warning"},
		Routing: &Routing{DomainStrategy: "AsIs"},
	}

	for i, e := range entries {
		out, err := parseShareLink(e.Link)
		if err != nil {
			return XrayMultiConfig{}, fmt.Errorf("link %d: %w", i, err)
		}
		inTag := fmt.Sprintf("in_%d", e.Port)
		outTag := fmt.Sprintf("proxy_%d", e.Port)
		out.Tag = outTag

		cfg.Inbounds = append(cfg.Inbounds, Inbound{
			Listen:   "127.0.0.1",
			Port:     e.Port,
			Protocol: "socks",
			Tag:      inTag,
			Settings: map[string]any{
				"udp":  true,
				"auth": "noauth",
			},
		})
		cfg.Outbounds = append(cfg.Outbounds, out)
		cfg.Routing.Rules = append(cfg.Routing.Rules, RoutingRule{
			Type:        "field",
			InboundTag:  []string{inTag},
			OutboundTag: outTag,
		})
	}
	// Fallback outbound.
	cfg.Outbounds = append(cfg.Outbounds, Outbound{
		Protocol: "freedom", Settings: map[string]any{}, Tag: "direct",
	})
	return cfg, nil
}

// XrayMultiConfig is the full config shape including routing.
type XrayMultiConfig struct {
	Log       map[string]string `json:"log"`
	Inbounds  []Inbound         `json:"inbounds"`
	Outbounds []Outbound        `json:"outbounds"`
	Routing   *Routing          `json:"routing,omitempty"`
}

// Routing holds xray routing rules.
type Routing struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []RoutingRule `json:"rules"`
}

// RoutingRule maps inbound tags to an outbound tag.
type RoutingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// WriteMultiJSON serializes a multi-outbound config to disk.
func WriteMultiJSON(cfg XrayMultiConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteJSON serializes a config to disk as indented JSON.
func WriteJSON(cfg XrayConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func parseShareLink(link string) (Outbound, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return Outbound{}, fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Outbound{}, fmt.Errorf("invalid port %q: %w", u.Port(), err)
	}
	q := u.Query()
	stream := buildStreamSettings(q)

	switch strings.ToLower(u.Scheme) {
	case "trojan":
		return Outbound{
			Protocol: "trojan",
			Settings: map[string]any{
				"servers": []map[string]any{
					{
						"address":  host,
						"port":     port,
						"password": u.User.Username(),
					},
				},
			},
			StreamSettings: stream,
			Tag:            "proxy",
		}, nil

	case "vless":
		encryption := q.Get("encryption")
		if encryption == "" {
			encryption = "none"
		}
		user := map[string]any{
			"id":         u.User.Username(),
			"encryption": encryption,
		}
		if flow := q.Get("flow"); flow != "" {
			user["flow"] = flow
		}
		return Outbound{
			Protocol: "vless",
			Settings: map[string]any{
				"vnext": []map[string]any{
					{
						"address": host,
						"port":    port,
						"users":   []map[string]any{user},
					},
				},
			},
			StreamSettings: stream,
			Tag:            "proxy",
		}, nil

	case "ss":
		method, password := parseSS(u)
		out := Outbound{
			Protocol: "shadowsocks",
			Settings: map[string]any{
				"servers": []map[string]any{
					{
						"address":  host,
						"port":     port,
						"method":   method,
						"password": password,
					},
				},
			},
			Tag: "proxy",
		}
		// If the link has a v2ray-plugin, add stream settings.
		if plugin := q.Get("plugin"); plugin != "" {
			out.StreamSettings = parseSSplugin(plugin)
		}
		return out, nil

	default:
		return Outbound{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

func buildStreamSettings(q url.Values) map[string]any {
	stream := map[string]any{}

	netType := q.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	stream["network"] = netType

	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	stream["security"] = security

	if security == "tls" {
		tls := map[string]any{}
		if sni := q.Get("sni"); sni != "" {
			tls["serverName"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		insecure := q.Get("allowInsecure")
		if insecure == "" {
			insecure = q.Get("insecure")
		}
		tls["allowInsecure"] = insecure == "1" || strings.EqualFold(insecure, "true")
		stream["tlsSettings"] = tls
	}

	if security == "reality" {
		reality := map[string]any{}
		if sni := q.Get("sni"); sni != "" {
			reality["serverName"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			reality["fingerprint"] = fp
		}
		if pbk := q.Get("pbk"); pbk != "" {
			reality["publicKey"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			reality["shortId"] = sid
		}
		if spx := q.Get("spx"); spx != "" {
			reality["spiderX"] = spx
		}
		stream["realitySettings"] = reality
	}

	switch netType {
	case "ws":
		ws := map[string]any{"path": "/"}
		if path := q.Get("path"); path != "" {
			ws["path"] = path
		}
		if host := q.Get("host"); host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		if svc := q.Get("serviceName"); svc != "" {
			grpc["serviceName"] = svc
		}
		stream["grpcSettings"] = grpc
	case "tcp":
		if q.Get("headerType") == "http" {
			stream["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http"},
			}
		}
	}
	return stream
}

// parseSS extracts method and password from an ss:// URL.
// Format: ss://base64(method:password)@host:port or ss://method:password@host:port
func parseSS(u *url.URL) (method, password string) {
	userInfo := u.User.String()
	// Try base64-decoding the userinfo.
	if decoded, err := base64.URLEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(decoded)
	} else if decoded, err := base64.RawURLEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(decoded)
	} else if decoded, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(decoded)
	}
	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return userInfo, ""
}

// parseSSplugin parses v2ray-plugin parameters into xray streamSettings.
func parseSSplugin(pluginStr string) map[string]any {
	stream := map[string]any{}
	params := map[string]string{}
	// Format: "v2ray-plugin;mode=websocket;host=example.com;path=/foo;tls"
	parts := strings.Split(pluginStr, ";")
	for _, p := range parts[1:] { // skip plugin name
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		} else {
			params[kv[0]] = "true"
		}
	}

	mode := params["mode"]
	if mode == "websocket" {
		stream["network"] = "ws"
		ws := map[string]any{}
		if path, ok := params["path"]; ok {
			ws["path"] = path
		} else {
			ws["path"] = "/"
		}
		if host, ok := params["host"]; ok {
			ws["headers"] = map[string]any{"Host": host}
		}
		stream["wsSettings"] = ws
	} else {
		stream["network"] = "tcp"
	}

	if _, useTLS := params["tls"]; useTLS {
		stream["security"] = "tls"
		tls := map[string]any{"allowInsecure": true}
		if host, ok := params["host"]; ok {
			tls["serverName"] = host
		}
		stream["tlsSettings"] = tls
	} else {
		stream["security"] = "none"
	}

	return stream
}

