// Package config builds Xray JSON configs from share links.
package config

import (
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
