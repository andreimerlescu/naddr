package ess

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	cfg, err := ConfigFromEnv(env(map[string]string{EnvDataPath: " /data/ip2asn.tsv "}))
	if err != nil || cfg.Path != "/data/ip2asn.tsv" || cfg.PollInterval != DefaultPollInterval {
		t.Fatalf("defaults = %+v, %v", cfg, err)
	}

	if _, err := ConfigFromEnv(env(nil)); !errors.Is(err, ErrDataPathUnset) {
		t.Fatalf("missing path error = %v", err)
	}

	for raw, want := range map[string]time.Duration{"5m": 5 * time.Minute, "off": 0, "0": 0, "DISABLED": 0} {
		cfg, err := ConfigFromEnv(env(map[string]string{EnvDataPath: "x", EnvDataPoll: raw}))
		if err != nil || cfg.PollInterval != want {
			t.Fatalf("%s=%q => %v, %v", EnvDataPoll, raw, cfg.PollInterval, err)
		}
	}

	for _, raw := range []string{"500ms", "soon", "-1s"} {
		if _, err := ConfigFromEnv(env(map[string]string{EnvDataPath: "x", EnvDataPoll: raw})); err == nil {
			t.Fatalf("%s=%q accepted", EnvDataPoll, raw)
		}
	}
}

func TestES(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn-combined.tsv.gz")
	if err := os.WriteFile(path, gzipBytes(t, testTSV), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvDataPath, path)
	t.Setenv(EnvDataPoll, "off")

	r, err := ES()
	if err != nil {
		t.Fatal(err)
	}
	if r.pollInterval != 0 {
		t.Fatalf("pollInterval = %v", r.pollInterval)
	}
	if _, err := r.LookupString("45.138.12.24"); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvDataPath, "")
	if _, err := ES(); !errors.Is(err, ErrDataPathUnset) {
		t.Fatalf("unset error = %v", err)
	}

	t.Setenv(EnvDataPath, filepath.Join(t.TempDir(), "missing.tsv"))
	if _, err := ES(); err == nil || !strings.Contains(err.Error(), IPtoASNDataURL) {
		t.Fatalf("missing file error = %v", err)
	}

	if _, err := OpenConfig(Config{}); !errors.Is(err, ErrDataPathUnset) {
		t.Fatalf("OpenConfig empty = %v", err)
	}
}
