package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

func TestRunServer(t *testing.T) {
	oldListen := listenTCP
	oldNotify := notifyContext
	oldGetenv := getenv

	defer func() {
		listenTCP = oldListen
		notifyContext = oldNotify
		getenv = oldGetenv
	}()

	getenv = func(key string) string {
		if key == EnvListenAddr {
			return ""
		}

		return ""
	}

	listenTCP = func(network, address string) (net.Listener, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}

		if address != DefaultListenAddr {
			t.Fatalf(
				"address = %q, want %q",
				address,
				DefaultListenAddr,
			)
		}

		return net.Listen("tcp", "127.0.0.1:0")
	}

	notifyContext = func(
		parent context.Context,
		_ ...os.Signal,
	) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancel()

		return ctx, func() {}
	}

	if err := runServer(mustTestResolver(t)); err != nil {
		t.Fatalf("runServer canceled startup: %v", err)
	}
}

func TestRunServerNilResolver(t *testing.T) {
	err := runServer(nil)

	if !errors.Is(err, ess.ErrNilResolver) {
		t.Fatalf(
			"runServer(nil) = %v, want %v",
			err,
			ess.ErrNilResolver,
		)
	}
}

func TestRunServerListenError(t *testing.T) {
	oldListen := listenTCP
	oldGetenv := getenv

	defer func() {
		listenTCP = oldListen
		getenv = oldGetenv
	}()

	want := errors.New("listen failed")

	getenv = func(key string) string {
		if key == EnvListenAddr {
			return "127.0.0.1:12345"
		}

		return ""
	}

	listenTCP = func(network, address string) (net.Listener, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}

		if address != "127.0.0.1:12345" {
			t.Fatalf(
				"address = %q, want %q",
				address,
				"127.0.0.1:12345",
			)
		}

		return nil, want
	}

	err := runServer(mustTestResolver(t))

	if !errors.Is(err, want) {
		t.Fatalf("runServer = %v, want %v", err, want)
	}
}

type errorListener struct {
	err error
}

func (l errorListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l errorListener) Close() error {
	return nil
}

func (l errorListener) Addr() net.Addr {
	return dummyAddr("error-listener")
}

type dummyAddr string

func (a dummyAddr) Network() string {
	return "test"
}

func (a dummyAddr) String() string {
	return string(a)
}

func TestServeUntilDoneErrorsAndShutdown(t *testing.T) {
	srv := NewHTTPServer(
		"",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)

	want := errors.New("accept failed")

	if err := serveUntilDone(
		context.Background(),
		srv,
		errorListener{err: want},
	); !errors.Is(err, want) {
		t.Fatalf("serve error = %v, want %v", err, want)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv = NewHTTPServer("", http.NotFoundHandler())

	if err := serveUntilDone(ctx, srv, ln); err != nil {
		t.Fatalf("graceful shutdown = %v", err)
	}
}

func TestNewHTTPServerConfiguration(t *testing.T) {
	srv := NewHTTPServer(
		"127.0.0.1:1",
		http.NotFoundHandler(),
	)

	if srv.Addr != "127.0.0.1:1" ||
		srv.ReadHeaderTimeout != 2*time.Second ||
		srv.WriteTimeout != 5*time.Second ||
		srv.IdleTimeout != 60*time.Second ||
		srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf(
			"unexpected server configuration: %+v",
			srv,
		)
	}

	if srv.Protocols == nil ||
		!srv.Protocols.HTTP1() ||
		!srv.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols = %v", srv.Protocols)
	}
}
