package ess

import (
	"context"
	"os"
	"time"
)

// WatchOptions configures Watch.
type WatchOptions struct {
	// Interval between checks. Zero uses the Resolver's configured interval
	// (NADDR_DATA_POLL via ES, or DefaultPollInterval via Open). If the
	// resulting interval is not positive, Watch returns nil immediately.
	Interval time.Duration

	// OnReload is called after a successful reload.
	OnReload func(Stats)

	// OnError is called when a reload fails or the file cannot be read.
	// The previous database keeps serving.
	OnError func(error)
}

// Watch polls the Resolver's source file and reloads it when it changes,
// until ctx is canceled. It returns nil on cancellation.
//
// A change is detected through size, modification time, and file identity,
// so both in-place writes and atomic renames are noticed. A changed file is
// loaded only after it has stayed unchanged for one full interval, so a
// download in progress is not loaded half-written. A file that fails to
// load is not retried until it changes again.
func (r *Resolver) Watch(ctx context.Context, opts WatchOptions) error {
	if r.current() == nil {
		return ErrNilResolver
	}
	if r.path == "" {
		return ErrNoSource
	}

	interval := opts.Interval
	if interval == 0 {
		interval = r.pollInterval
	}
	if interval <= 0 {
		return nil
	}

	report := func(err error) {
		if opts.OnError != nil {
			opts.OnError(err)
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var pending, rejected os.FileInfo
	statFailing := false

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		cur, err := os.Stat(r.path)
		if err != nil {
			pending = nil
			if !statFailing {
				statFailing = true
				report(err)
			}
			continue
		}
		statFailing = false

		if loaded := r.current().info; loaded != nil && sameFileState(loaded, cur) {
			pending = nil
			continue
		}
		if rejected != nil && sameFileState(rejected, cur) {
			pending = nil
			continue
		}
		if pending == nil || !sameFileState(pending, cur) {
			pending = cur
			continue
		}

		pending = nil
		if err := r.Reload(); err != nil {
			rejected = cur
			report(err)
			continue
		}
		rejected = nil

		if opts.OnReload != nil {
			opts.OnReload(r.Stats())
		}
	}
}

func sameFileState(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
