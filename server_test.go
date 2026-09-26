package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

func testConfig() Config {
	return Config{
		Listen:         DefaultListenAddr,
		LogFormat:      "text",
		TrustedProxies: loopbackPrefixes(),
		AllowedHosts:   defaultAllowedHosts("127.0.0.1"),
	}
}

func stubServerHooks(t *testing.T) {
	t.Helper()
	oldListen, oldNotify := listenTCP, notifyContext
	t.Cleanup(func() {
		listenTCP = oldListen
		notifyContext = oldNotify
	})
}

func TestRunServerCanceledStartup(t *testing.T) {
	stubServerHooks(t)

	listenTCP = func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != DefaultListenAddr {
			t.Fatalf("listen(%q, %q)", network, address)
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}
	notifyContext = func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}

	// A file-backed resolver exercises the watcher goroutine's shutdown.
	path := filepath.Join(t.TempDir(), "db.tsv")
	if err := os.WriteFile(path, []byte(testTSV), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := ess.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := runServer(testConfig(), resolver, discardLogger()); err != nil {
		t.Fatalf("runServer canceled startup: %v", err)
	}
}

func TestRunServerNilResolver(t *testing.T) {
	if err := runServer(testConfig(), nil, discardLogger()); !errors.Is(err, ess.ErrNilResolver) {
		t.Fatalf("runServer(nil) = %v", err)
	}
}

func TestRunServerListenError(t *testing.T) {
	stubServerHooks(t)

	want := errors.New("listen failed")
	listenTCP = func(string, string) (net.Listener, error) { return nil, want }

	if err := runServer(testConfig(), mustTestResolver(t), discardLogger()); !errors.Is(err, want) {
		t.Fatalf("runServer = %v, want %v", err, want)
	}
}

// startServer runs runServer on an ephemeral port and returns its address
// and a stop function that asserts a clean shutdown.
func startServer(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	stubServerHooks(t)

	ctx, cancel := context.WithCancel(context.Background())
	notifyContext = func(context.Context, ...os.Signal) (context.Context, context.CancelFunc) {
		return ctx, func() {}
	}

	lnCh := make(chan net.Listener, 1)
	listenTCP = func(string, string) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			lnCh <- ln
		}
		return ln, err
	}

	errc := make(chan error, 1)
	resolver := mustTestResolver(t)
	go func() { errc <- runServer(cfg, resolver, discardLogger()) }()

	var addr string
	select {
	case ln := <-lnCh:
		addr = ln.Addr().String()
	case err := <-errc:
		t.Fatalf("runServer exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}

	return addr, func() {
		cancel()
		if err := <-errc; err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	}
}

func TestRunServerServesHTTP(t *testing.T) {
	addr, stop := startServer(t, testConfig())
	defer stop()

	resp, err := http.Get("http://" + addr + "/ip?addr=45.138.12.24")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
}

func TestRunServerServesTLSWithHTTP2(t *testing.T) {
	certFile, keyFile, pool := writeSelfSignedCert(t)

	cfg := testConfig()
	cfg.TLSCert, cfg.TLSKey = certFile, keyFile

	addr, stop := startServer(t, cfg)
	defer stop()

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("status = %d proto = %s", resp.StatusCode, resp.Proto)
	}
}

type errorListener struct{ err error }

func (l errorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errorListener) Close() error              { return nil }
func (l errorListener) Addr() net.Addr            { return dummyAddr("error-listener") }

type dummyAddr string

func (a dummyAddr) Network() string { return "test" }
func (a dummyAddr) String() string  { return string(a) }

func TestServeUntilDoneErrorsAndShutdown(t *testing.T) {
	srv := NewHTTPServer("", http.NotFoundHandler(), false)
	want := errors.New("accept failed")

	err := serveUntilDone(context.Background(), srv, func() error {
		return srv.Serve(errorListener{err: want})
	})
	if !errors.Is(err, want) {
		t.Fatalf("serve error = %v, want %v", err, want)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv = NewHTTPServer("", http.NotFoundHandler(), false)
	if err := serveUntilDone(ctx, srv, func() error { return srv.Serve(ln) }); err != nil {
		t.Fatalf("graceful shutdown = %v", err)
	}
}

func TestNewHTTPServerConfiguration(t *testing.T) {
	srv := NewHTTPServer("127.0.0.1:1", http.NotFoundHandler(), false)

	if srv.Addr != "127.0.0.1:1" ||
		srv.ReadHeaderTimeout != 2*time.Second ||
		srv.ReadTimeout != 5*time.Second ||
		srv.WriteTimeout != 5*time.Second ||
		srv.IdleTimeout != 60*time.Second ||
		srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("unexpected server configuration: %+v", srv)
	}
	if !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() || srv.Protocols.HTTP2() {
		t.Fatalf("cleartext protocols = %v", srv.Protocols)
	}
	if srv.TLSConfig != nil {
		t.Fatal("cleartext server has TLS config")
	}

	srv = NewHTTPServer("127.0.0.1:1", http.NotFoundHandler(), true)
	if !srv.Protocols.HTTP1() || !srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2() {
		t.Fatalf("TLS protocols = %v", srv.Protocols)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config = %+v", srv.TLSConfig)
	}
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "naddr test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}
