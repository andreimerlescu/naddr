package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/andreimerlescu/naddr/ess"
)

func preserveDefaultLogger(t *testing.T) {
	t.Helper()
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, mapEnv(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	if stdout.String() != BinaryVersion()+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunHelpAndBadFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, mapEnv(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("-h exit = %d", code)
	}
	if !strings.Contains(stderr.String(), ess.EnvDataPath) {
		t.Fatalf("usage does not mention %s: %s", ess.EnvDataPath, stderr.String())
	}

	stderr.Reset()
	if code := run([]string{"-nope"}, mapEnv(nil), &stdout, &stderr); code != 2 {
		t.Fatalf("bad flag exit = %d", code)
	}
}

func TestRunRequiresDataPath(t *testing.T) {
	preserveDefaultLogger(t)
	t.Setenv(ess.EnvDataPath, "")

	var stdout, stderr bytes.Buffer
	if code := run(nil, mapEnv(nil), &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), ess.EnvDataPath) {
		t.Fatalf("stderr does not name %s: %s", ess.EnvDataPath, stderr.String())
	}
}

func TestBinaryVersion(t *testing.T) {
	if v := BinaryVersion(); !strings.HasPrefix(v, "v") {
		t.Fatalf("BinaryVersion = %q", v)
	}
}
