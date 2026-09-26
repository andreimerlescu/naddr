package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := parseConfig(nil, mapEnv(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != DefaultListenAddr {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	if cfg.LogLevel != slog.LevelInfo || cfg.LogFormat != "text" || cfg.AccessLog {
		t.Fatalf("logging = %v %q %v", cfg.LogLevel, cfg.LogFormat, cfg.AccessLog)
	}
	if !slices.Equal(cfg.TrustedProxies, loopbackPrefixes()) {
		t.Fatalf("TrustedProxies = %v", cfg.TrustedProxies)
	}
	if !slices.Equal(cfg.AllowedHosts, []string{"localhost", "127.0.0.1", "::1"}) {
		t.Fatalf("AllowedHosts = %v", cfg.AllowedHosts)
	}
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		t.Fatal("TLS should be off by default")
	}
}

func TestParseConfigEnvAndFlagPrecedence(t *testing.T) {
	env := mapEnv(map[string]string{
		EnvListenAddr:     "10.0.0.5:9000",
		EnvLogLevel:       "debug",
		EnvLogFormat:      "JSON",
		EnvAccessLog:      "true",
		EnvTrustedProxies: "10.0.0.0/8, 192.168.1.1",
		EnvTLSCert:        "/etc/naddr/cert.pem",
		EnvTLSKey:         "/etc/naddr/key.pem",
	})

	cfg, err := parseConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "10.0.0.5:9000" || cfg.LogLevel != slog.LevelDebug ||
		cfg.LogFormat != "json" || !cfg.AccessLog {
		t.Fatalf("env config = %+v", cfg)
	}
	wantProxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.1/32"),
	}
	if !slices.Equal(cfg.TrustedProxies, wantProxies) {
		t.Fatalf("TrustedProxies = %v", cfg.TrustedProxies)
	}
	if !slices.Contains(cfg.AllowedHosts, "10.0.0.5") {
		t.Fatalf("listen host missing from AllowedHosts: %v", cfg.AllowedHosts)
	}

	cfg, err = parseConfig([]string{"-listen", "127.0.0.1:7000", "-access-log=false", "-log-level", "warn"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:7000" || cfg.AccessLog || cfg.LogLevel != slog.LevelWarn {
		t.Fatalf("flags did not override env: %+v", cfg)
	}
}

func TestParseConfigHostsAndProxies(t *testing.T) {
	cfg, err := parseConfig([]string{"-listen", "0.0.0.0:8080"}, mapEnv(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.AllowedHosts, []string{"localhost", "127.0.0.1", "::1"}) {
		t.Fatalf("unspecified listen host leaked into AllowedHosts: %v", cfg.AllowedHosts)
	}

	cfg, err = parseConfig([]string{"-allowed-hosts", "*"}, mapEnv(nil), io.Discard)
	if err != nil || cfg.AllowedHosts != nil {
		t.Fatalf("'*' = %v, %v", cfg.AllowedHosts, err)
	}

	cfg, err = parseConfig([]string{"-allowed-hosts", "naddr.internal, Example.COM:443,[::1]"}, mapEnv(nil), io.Discard)
	if err != nil || !slices.Equal(cfg.AllowedHosts, []string{"naddr.internal", "example.com", "::1"}) {
		t.Fatalf("hosts = %v, %v", cfg.AllowedHosts, err)
	}

	cfg, err = parseConfig([]string{"-trusted-proxies", "none"}, mapEnv(nil), io.Discard)
	if err != nil || cfg.TrustedProxies == nil || len(cfg.TrustedProxies) != 0 {
		t.Fatalf("none = %v, %v", cfg.TrustedProxies, err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"cert without key", []string{"-tls-cert", "c.pem"}, nil, "set together"},
		{"key without cert", []string{"-tls-key", "k.pem"}, nil, "set together"},
		{"bad log level", []string{"-log-level", "loud"}, nil, "log level"},
		{"bad log format", []string{"-log-format", "xml"}, nil, "log format"},
		{"bad listen", []string{"-listen", "nope"}, nil, "listen address"},
		{"bad proxy", []string{"-trusted-proxies", "x"}, nil, "invalid address"},
		{"bad proxy cidr", []string{"-trusted-proxies", "10.0.0.0/99"}, nil, "invalid CIDR"},
		{"none combined", []string{"-trusted-proxies", "none,loopback"}, nil, "cannot be combined"},
		{"star combined", []string{"-allowed-hosts", "*,a"}, nil, "must be used alone"},
		{"bad access log env", nil, map[string]string{EnvAccessLog: "maybe"}, EnvAccessLog},
		{"extra args", []string{"serve"}, nil, "unexpected arguments"},
		{"unknown flag", []string{"-nope"}, nil, "not defined"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args, mapEnv(tc.env), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestNewLoggerFormats(t *testing.T) {
	var buf bytes.Buffer
	newLogger(Config{LogFormat: "json", LogLevel: slog.LevelInfo}, &buf).Info("hello", "k", "v")
	if !strings.Contains(buf.String(), `"msg":"hello"`) {
		t.Fatalf("json log = %q", buf.String())
	}

	buf.Reset()
	newLogger(Config{LogFormat: "text", LogLevel: slog.LevelWarn}, &buf).Info("hidden")
	if buf.Len() != 0 {
		t.Fatalf("level filter failed: %q", buf.String())
	}
}
