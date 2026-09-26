package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

var (
	listenTCP               = net.Listen
	notifyContext           = signal.NotifyContext
	gracefulShutdownTimeout = 5 * time.Second
)

func runServer(cfg Config, resolver *ess.Resolver, logger *slog.Logger) error {
	if resolver == nil {
		return ess.ErrNilResolver
	}
	if logger == nil {
		logger = slog.Default()
	}

	ln, err := listenTCP("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	useTLS := cfg.TLSCert != ""
	handler := NewHandler(resolver, HandlerOptions{
		TrustedProxies: cfg.TrustedProxies,
		AllowedHosts:   cfg.AllowedHosts,
		AccessLog:      cfg.AccessLog,
		Logger:         logger,
	})
	srv := NewHTTPServer(cfg.Listen, handler, useTLS)
	srv.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelWarn)

	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Deferred in LIFO order: cancel the watcher, then wait for it to exit.
	var wg sync.WaitGroup
	defer wg.Wait()
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()

	wg.Go(func() {
		err := resolver.Watch(watchCtx, ess.WatchOptions{
			OnReload: func(s ess.Stats) {
				logger.Info("naddr database reloaded", statsAttrs(s)...)
			},
			OnError: func(err error) {
				logger.Error("naddr database reload failed; serving previous database", "error", err)
			},
		})
		if err != nil && !errors.Is(err, ess.ErrNoSource) {
			logger.Error("naddr database watcher stopped", "error", err)
		}
	})

	serve := func() error { return srv.Serve(ln) }
	if useTLS {
		serve = func() error { return srv.ServeTLS(ln, cfg.TLSCert, cfg.TLSKey) }
	}

	attrs := []any{"version", BinaryVersion(), "listen", ln.Addr().String(), "tls", useTLS}
	logger.Info("naddr ready", append(attrs, statsAttrs(resolver.Stats())...)...)

	return serveUntilDone(ctx, srv, serve)
}

func statsAttrs(s ess.Stats) []any {
	return []any{
		"source", s.Source,
		"loaded_at", s.LoadedAt,
		"ipv4_ranges", s.IPv4Ranges,
		"ipv6_ranges", s.IPv6Ranges,
		"asns", s.ASNs,
		"reloads", s.Reloads,
	}
}

// NewHTTPServer applies naddr's hardened server defaults. Without TLS it
// serves HTTP/1.1 and cleartext HTTP/2 (h2c); with TLS, HTTP/1.1 and HTTP/2.
func NewHTTPServer(addr string, handler http.Handler, useTLS bool) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		Protocols:         protocols,
	}

	if useTLS {
		protocols.SetHTTP2(true)
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}

	return srv
}

// serveUntilDone runs serve until it fails or ctx is canceled, then shuts
// the server down gracefully.
func serveUntilDone(ctx context.Context, srv *http.Server, serve func() error) error {
	errc := make(chan error, 1)
	go func() { errc <- serve() }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		shutdownErr := srv.Shutdown(shutdownCtx)
		cancel()

		if shutdownErr != nil {
			_ = srv.Close()
		}

		serveErr := <-errc
		if shutdownErr != nil {
			return shutdownErr
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}
