// Package mpconfig loads runtime configuration for the mp binary.
//
// Settings come from a JSON file. Most values can be overridden by
// command-line flags so single-shot invocations stay convenient. Flags
// that are not explicitly set fall back to the file, then to defaults.
package mpconfig

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// File is the on-disk shape. Both client and server blocks are
// optional — only the one matching the chosen subcommand needs to be
// populated.
type File struct {
	Client *ClientFile `json:"client,omitempty"`
	Server *ServerFile `json:"server,omitempty"`
}

// ClientFile describes the client subcommand's settings.
type ClientFile struct {
	// Listen is the local SOCKS5 frontend port (or host:port). Apps
	// (browsers, miners, anything) connect here.
	Listen string `json:"listen"`
	// Server is the remote mp-server address (host:port).
	Server string `json:"server"`
	// XrayLinks is the path to the file with vless/trojan share links,
	// one per line. One xray instance is spawned per link.
	XrayLinks string `json:"xrayLinks"`
	// XrayBin is the path to xray.exe / xray. Defaults to ./xray-core/xray(.exe).
	XrayBin string `json:"xrayBin,omitempty"`
	// XrayBasePort is the first SOCKS5 port to allocate to the spawned
	// xrays. Defaults to 1080. Subsequent xrays use 1081, 1082, ...
	XrayBasePort int `json:"xrayBasePort,omitempty"`
	// ConfigsDir is where generated xray JSON configs are written.
	// Defaults to ./configs.
	ConfigsDir string `json:"configsDir,omitempty"`
	// ProbeInterval is how often each xray instance is probed. Default 30s.
	ProbeInterval string `json:"probeInterval,omitempty"`
	// ProbeTimeout is the per-instance probe timeout. Default 10s.
	ProbeTimeout string `json:"probeTimeout,omitempty"`
	// HandshakeTimeout bounds tunnel HELLO/ACK round-trips. Default 10s.
	HandshakeTimeout string `json:"handshakeTimeout,omitempty"`
	// PSK is the 32-byte pre-shared key, hex-encoded. Required.
	// Generate with `mp gen-key`.
	PSK string `json:"psk"`
}

// ServerFile describes the server subcommand's settings.
type ServerFile struct {
	Listen           string `json:"listen"`
	HandshakeTimeout string `json:"handshakeTimeout,omitempty"`
	// PSK matches the client's. Required.
	PSK string `json:"psk"`
}

// ClientConfig is the resolved client configuration.
type ClientConfig struct {
	Listen           string
	Server           string
	XrayLinks        string
	XrayBin          string
	XrayBasePort     int
	ConfigsDir       string
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	HandshakeTimeout time.Duration
	// PSK is the 32-byte pre-shared key (raw bytes, decoded from hex).
	PSK []byte
}

// ServerConfig is the resolved server configuration.
type ServerConfig struct {
	Listen           string
	HandshakeTimeout time.Duration
	PSK              []byte
}

// Load reads a JSON config file. Returns an empty File if path is
// empty.
func Load(path string) (File, error) {
	if path == "" {
		return File{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return f, nil
}

// NormalizeListen turns a port-only string ("3333") into a full
// host:port. defaultHost is used when the input has no host part.
// Already-formed "host:port" strings are returned unchanged.
func NormalizeListen(in, defaultHost string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", nil
	}
	if !strings.Contains(in, ":") {
		if _, err := strconv.Atoi(in); err != nil {
			return "", fmt.Errorf("listen %q: not a port number", in)
		}
		return defaultHost + ":" + in, nil
	}
	return in, nil
}

func parseDurOr(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return d, nil
}

// ResolveClient merges file-derived defaults with command-line
// overrides. Each non-zero override wins; a zero override falls back
// to the file value, then to a default.
type ClientOverrides struct {
	Listen           string
	Server           string
	XrayLinks        string
	XrayBin          string
	XrayBasePort     int
	ConfigsDir       string
	HandshakeTimeout time.Duration
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	PSK              string // hex-encoded; overrides file.PSK if non-empty
}

func ResolveClient(file *ClientFile, ov ClientOverrides) (ClientConfig, error) {
	cfg := ClientConfig{
		Listen:           ov.Listen,
		Server:           ov.Server,
		XrayLinks:        ov.XrayLinks,
		XrayBin:          ov.XrayBin,
		XrayBasePort:     ov.XrayBasePort,
		ConfigsDir:       ov.ConfigsDir,
		HandshakeTimeout: ov.HandshakeTimeout,
		ProbeInterval:    ov.ProbeInterval,
		ProbeTimeout:     ov.ProbeTimeout,
	}
	if file != nil {
		if cfg.Listen == "" {
			cfg.Listen = file.Listen
		}
		if cfg.Server == "" {
			cfg.Server = file.Server
		}
		if cfg.XrayLinks == "" {
			cfg.XrayLinks = file.XrayLinks
		}
		if cfg.XrayBin == "" {
			cfg.XrayBin = file.XrayBin
		}
		if cfg.XrayBasePort == 0 {
			cfg.XrayBasePort = file.XrayBasePort
		}
		if cfg.ConfigsDir == "" {
			cfg.ConfigsDir = file.ConfigsDir
		}
		if cfg.HandshakeTimeout == 0 {
			d, err := parseDurOr(file.HandshakeTimeout, 0)
			if err != nil {
				return cfg, fmt.Errorf("client.handshakeTimeout: %w", err)
			}
			cfg.HandshakeTimeout = d
		}
		if cfg.ProbeInterval == 0 {
			d, err := parseDurOr(file.ProbeInterval, 0)
			if err != nil {
				return cfg, fmt.Errorf("client.probeInterval: %w", err)
			}
			cfg.ProbeInterval = d
		}
		if cfg.ProbeTimeout == 0 {
			d, err := parseDurOr(file.ProbeTimeout, 0)
			if err != nil {
				return cfg, fmt.Errorf("client.probeTimeout: %w", err)
			}
			cfg.ProbeTimeout = d
		}
	}

	// Defaults.
	if cfg.Listen == "" {
		cfg.Listen = "2080"
	}
	if cfg.XrayLinks == "" {
		cfg.XrayLinks = "xrays.txt"
	}
	if cfg.XrayBasePort == 0 {
		cfg.XrayBasePort = 1080
	}
	if cfg.ConfigsDir == "" {
		cfg.ConfigsDir = "configs"
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 3 * time.Second
	}
	if cfg.ProbeInterval == 0 {
		cfg.ProbeInterval = 30 * time.Second
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}

	listenNorm, err := NormalizeListen(cfg.Listen, "127.0.0.1")
	if err != nil {
		return cfg, fmt.Errorf("client.listen: %w", err)
	}
	cfg.Listen = listenNorm

	if cfg.Server == "" {
		return cfg, fmt.Errorf("client: server address is required")
	}

	pskHex := ov.PSK
	if pskHex == "" && file != nil {
		pskHex = file.PSK
	}
	psk, err := decodePSK(pskHex)
	if err != nil {
		return cfg, fmt.Errorf("client.psk: %w", err)
	}
	cfg.PSK = psk

	return cfg, nil
}

// ResolveServer merges file-derived defaults with command-line overrides.
func ResolveServer(file *ServerFile, listen, pskHex string, handshakeTO time.Duration) (ServerConfig, error) {
	cfg := ServerConfig{
		Listen:           listen,
		HandshakeTimeout: handshakeTO,
	}
	if file != nil {
		if cfg.Listen == "" {
			cfg.Listen = file.Listen
		}
		if cfg.HandshakeTimeout == 0 {
			d, err := parseDurOr(file.HandshakeTimeout, 0)
			if err != nil {
				return cfg, fmt.Errorf("server.handshakeTimeout: %w", err)
			}
			cfg.HandshakeTimeout = d
		}
	}
	if cfg.Listen == "" {
		cfg.Listen = "7000"
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	listenNorm, err := NormalizeListen(cfg.Listen, "0.0.0.0")
	if err != nil {
		return cfg, fmt.Errorf("server.listen: %w", err)
	}
	cfg.Listen = listenNorm

	if pskHex == "" && file != nil {
		pskHex = file.PSK
	}
	psk, err := decodePSK(pskHex)
	if err != nil {
		return cfg, fmt.Errorf("server.psk: %w", err)
	}
	cfg.PSK = psk

	return cfg, nil
}

// decodePSK validates and hex-decodes a PSK string. Required field.
func decodePSK(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("required (run `mp gen-key` to create one)")
	}
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("must decode to 32 bytes, got %d", len(b))
	}
	return b, nil
}

