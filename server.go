package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

const (
	DefaultListenAddr = "127.0.0.1:8080"
	EnvListenAddr     = "NADDR_LISTEN"
)

var gracefulShutdownTimeout = 5 * time.Second

var (
	listenTCP = func(network, address string) (net.Listener, error) {
		return net.Listen(network, address)
	}

	notifyContext = signal.NotifyContext
	getenv        = os.Getenv
)

func runServer(resolver *ess.Resolver) error {
	if resolver == nil {
		return ess.ErrNilResolver
	}

	addr := strings.TrimSpace(getenv(EnvListenAddr))
	if addr == "" {
		addr = DefaultListenAddr
	}

	ln, err := listenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := NewHTTPServer(addr, NewHandler(resolver))

	ctx, stop := notifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	stats := resolver.Stats()

	slog.Info(
		"naddr ready",
		"listen", ln.Addr().String(),
		"ipv4_ranges", stats.IPv4Ranges,
		"ipv6_ranges", stats.IPv6Ranges,
		"asn_metadata", stats.ASNMetadata,
		"descriptions", stats.Descriptions,
	)

	return serveUntilDone(ctx, srv, ln)
}

// NewHTTPServer applies the hardened HTTP server defaults used by naddr.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		Protocols:         protocols,
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return NewHTTPServer(addr, handler)
}

func serveUntilDone(
	ctx context.Context,
	srv *http.Server,
	ln net.Listener,
) error {
	errc := make(chan error, 1)

	go func() {
		errc <- srv.Serve(ln)
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			gracefulShutdownTimeout,
		)

		shutdownErr := srv.Shutdown(shutdownCtx)
		cancel()

		if shutdownErr != nil {
			_ = srv.Close()
		}

		<-errc

		if shutdownErr != nil {
			return shutdownErr
		}

		return nil
	}
}
