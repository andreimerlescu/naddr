package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/andreimerlescu/naddr/ess"
)

// Settings scoped to running the naddr binary. Data-source settings
// (NADDR_DATA, NADDR_DATA_POLL) belong to package ess.
const (
	DefaultListenAddr = "127.0.0.1:8080"

	EnvListenAddr     = "NADDR_LISTEN"
	EnvTLSCert        = "NADDR_TLS_CERT"
	EnvTLSKey         = "NADDR_TLS_KEY"
	EnvLogLevel       = "NADDR_LOG_LEVEL"
	EnvLogFormat      = "NADDR_LOG_FORMAT"
	EnvAccessLog      = "NADDR_ACCESS_LOG"
	EnvTrustedProxies = "NADDR_TRUSTED_PROXIES"
	EnvAllowedHosts   = "NADDR_ALLOWED_HOSTS"
)

// Config holds runtime settings for the naddr binary.
type Config struct {
	Listen    string
	TLSCert   string
	TLSKey    string
	LogLevel  slog.Level
	LogFormat string
	AccessLog bool

	// TrustedProxies are peers whose X-Forwarded-For / X-Real-IP headers
	// are honored by /my. Empty means no peer is trusted.
	TrustedProxies []netip.Prefix

	// AllowedHosts is the Host header allowlist. nil disables the check.
	AllowedHosts []string

	ShowVersion bool
}

// parseConfig resolves flags, falling back to environment variables, then
// to defaults. Flags win over environment variables.
func parseConfig(args []string, getenv func(string) string, output io.Writer) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	env := func(key, fallback string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return fallback
	}

	accessLog := false
	if raw := env(EnvAccessLog, ""); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvAccessLog, err)
		}
		accessLog = v
	}

	var (
		cfg      Config
		logLevel string
		trusted  string
		hosts    string
	)

	fs := flag.NewFlagSet("naddr", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(),
			"Usage: naddr [flags]\n\n"+
				"%s must name an IPtoASN TSV file (plain or .gz).\n"+
				"Download: %s\n\nFlags:\n",
			ess.EnvDataPath, ess.IPtoASNDataURL)
		fs.PrintDefaults()
	}

	fs.StringVar(&cfg.Listen, "listen", env(EnvListenAddr, DefaultListenAddr),
		"listen `host:port` ($"+EnvListenAddr+")")
	fs.StringVar(&cfg.TLSCert, "tls-cert", env(EnvTLSCert, ""),
		"TLS certificate `file`; requires -tls-key ($"+EnvTLSCert+")")
	fs.StringVar(&cfg.TLSKey, "tls-key", env(EnvTLSKey, ""),
		"TLS private key `file`; requires -tls-cert ($"+EnvTLSKey+")")
	fs.StringVar(&logLevel, "log-level", env(EnvLogLevel, "info"),
		"debug, info, warn, or error ($"+EnvLogLevel+")")
	fs.StringVar(&cfg.LogFormat, "log-format", env(EnvLogFormat, "text"),
		"text or json ($"+EnvLogFormat+")")
	fs.BoolVar(&cfg.AccessLog, "access-log", accessLog,
		"log every request ($"+EnvAccessLog+")")
	fs.StringVar(&trusted, "trusted-proxies", env(EnvTrustedProxies, "loopback"),
		"comma-separated CIDRs/IPs, 'loopback', or 'none' ($"+EnvTrustedProxies+")")
	fs.StringVar(&hosts, "allowed-hosts", env(EnvAllowedHosts, ""),
		"comma-separated Host header allowlist, or '*' to disable; default: localhost names plus the -listen host ($"+EnvAllowedHosts+")")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.ShowVersion {
		return cfg, nil
	}

	listenHost, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return Config{}, fmt.Errorf("invalid listen address %q: %w", cfg.Listen, err)
	}

	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return Config{}, errors.New("-tls-cert and -tls-key must be set together")
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return Config{}, fmt.Errorf("invalid log level %q", logLevel)
	}

	cfg.LogFormat = strings.ToLower(strings.TrimSpace(cfg.LogFormat))
	if cfg.LogFormat != "text" && cfg.LogFormat != "json" {
		return Config{}, fmt.Errorf("invalid log format %q: want text or json", cfg.LogFormat)
	}

	if cfg.TrustedProxies, err = parseTrustedProxies(trusted); err != nil {
		return Config{}, err
	}
	if cfg.AllowedHosts, err = parseAllowedHosts(hosts, listenHost); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func newLogger(cfg Config, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func loopbackPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

func parseTrustedProxies(spec string) ([]netip.Prefix, error) {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "none") {
		return []netip.Prefix{}, nil
	}

	out := []netip.Prefix{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "":
			continue
		case strings.EqualFold(tok, "none"):
			return nil, errors.New("trusted proxies: 'none' cannot be combined with other entries")
		case strings.EqualFold(tok, "loopback"):
			out = append(out, loopbackPrefixes()...)
		case strings.Contains(tok, "/"):
			p, err := netip.ParsePrefix(tok)
			if err != nil || p.Addr().Is4In6() {
				return nil, fmt.Errorf("trusted proxies: invalid CIDR %q", tok)
			}
			out = append(out, p.Masked())
		default:
			a, err := ess.ParseAddr(tok)
			if err != nil {
				return nil, fmt.Errorf("trusted proxies: invalid address %q", tok)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

func parseAllowedHosts(spec, listenHost string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "*":
		return nil, nil
	case "":
		return defaultAllowedHosts(listenHost), nil
	}

	var out []string
	for _, tok := range strings.Split(spec, ",") {
		h := normalizeHost(tok)
		if h == "" {
			continue
		}
		if h == "*" {
			return nil, errors.New("allowed hosts: '*' must be used alone")
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("allowed hosts: no valid entries")
	}
	return out, nil
}

// defaultAllowedHosts permits loopback names plus the concrete listen host.
// An unspecified listen host (0.0.0.0, ::) adds nothing: operators exposing
// naddr must name the hosts clients will use.
func defaultAllowedHosts(listenHost string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	h := normalizeHost(listenHost)
	if h == "" || slices.Contains(hosts, h) {
		return hosts
	}
	if a, err := netip.ParseAddr(h); err == nil && a.IsUnspecified() {
		return hosts
	}
	return append(hosts, h)
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}
