package ess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const watchInterval = 5 * time.Millisecond

// startWatch runs Watch in the background and stops it at test cleanup.
func startWatch(t *testing.T, r *Resolver) (<-chan Stats, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	reloads := make(chan Stats, 16)
	errs := make(chan error, 16)
	done := make(chan error, 1)

	go func() {
		done <- r.Watch(ctx, WatchOptions{
			Interval: watchInterval,
			OnReload: func(s Stats) {
				select {
				case reloads <- s:
				default:
				}
			},
			OnError: func(err error) {
				select {
				case errs <- err:
				default:
				}
			},
		})
	}()

	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Watch returned %v", err)
		}
	})

	return reloads, errs
}

func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

func openTemp(t *testing.T, data string) (*Resolver, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn-combined.tsv")
	writeFile(t, path, data)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return r, path
}

func TestWatchReloadsInPlaceWrite(t *testing.T) {
	r, path := openTemp(t, testTSV)
	reloads, _ := startWatch(t, r)

	writeFile(t, path, extendedTSV)

	s := waitFor(t, reloads, "reload")
	if s.Reloads < 1 {
		t.Fatalf("stats = %+v", s)
	}
	if _, err := r.LookupString("8.8.8.8"); err != nil {
		t.Fatalf("new range missing after reload: %v", err)
	}
}

func TestWatchReloadsAtomicRename(t *testing.T) {
	r, path := openTemp(t, extendedTSV)
	reloads, _ := startWatch(t, r)

	tmp := path + ".new"
	writeFile(t, tmp, testTSV)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	waitFor(t, reloads, "reload")
	if _, err := r.LookupString("8.8.8.8"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("removed range still present: %v", err)
	}
}

func TestWatchKeepsServingOnBadFile(t *testing.T) {
	r, path := openTemp(t, testTSV)
	reloads, errs := startWatch(t, r)

	writeFile(t, path, "garbage\n")
	waitFor(t, errs, "reload error")

	if _, err := r.LookupString("45.138.12.24"); err != nil {
		t.Fatalf("previous database lost: %v", err)
	}
	if s := r.Stats(); s.LastReloadError == "" || s.Reloads != 0 {
		t.Fatalf("stats after bad file = %+v", s)
	}

	writeFile(t, path, extendedTSV)
	waitFor(t, reloads, "recovery reload")

	if s := r.Stats(); s.LastReloadError != "" || s.Reloads != 1 {
		t.Fatalf("stats after recovery = %+v", s)
	}
}

func TestWatchReportsMissingFile(t *testing.T) {
	r, path := openTemp(t, testTSV)
	_, errs := startWatch(t, r)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := waitFor(t, errs, "stat error"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v", err)
	}
	if _, err := r.LookupString("45.138.12.24"); err != nil {
		t.Fatalf("database lost when file vanished: %v", err)
	}
}

func TestWatchPreconditions(t *testing.T) {
	ctx := context.Background()

	var nilResolver *Resolver
	if err := nilResolver.Watch(ctx, WatchOptions{}); !errors.Is(err, ErrNilResolver) {
		t.Fatalf("nil = %v", err)
	}
	if err := mustTestResolver(t).Watch(ctx, WatchOptions{}); !errors.Is(err, ErrNoSource) {
		t.Fatalf("Load-based = %v", err)
	}

	r, _ := openTemp(t, testTSV)
	r.pollInterval = 0
	if err := r.Watch(ctx, WatchOptions{}); err != nil {
		t.Fatalf("disabled watch = %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.Watch(canceled, WatchOptions{Interval: time.Hour}); err != nil {
		t.Fatalf("canceled watch = %v", err)
	}
}
