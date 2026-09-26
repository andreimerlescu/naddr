package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andreimerlescu/naddr/ess"
)

const testTSV = "" +
	"range_start\trange_end\tAS_number\tcountry_code\tAS_description\n" +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"64.23.176.0\t64.23.191.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"64.24.0.0\t64.24.0.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"100.64.0.0\t100.64.0.255\t0\tNone\tNot routed\n" +
	"2001:1948::\t2001:1948:ffff:ffff:ffff:ffff:ffff:ffff\t210\tUS\tInternet2\n"

const testHost = "127.0.0.1:8080"

func mustTestResolver(t testing.TB) *ess.Resolver {
	t.Helper()

	resolver, err := ess.Load(strings.NewReader(testTSV))
	if err != nil {
		t.Fatalf("ess.Load: %v", err)
	}

	return resolver
}

func defaultHandlerOptions() HandlerOptions {
	return HandlerOptions{
		TrustedProxies: loopbackPrefixes(),
		AllowedHosts:   defaultAllowedHosts("127.0.0.1"),
		Logger:         discardLogger(),
	}
}

func newTestHandler(t testing.TB) http.Handler {
	t.Helper()
	return NewHandler(mustTestResolver(t), defaultHandlerOptions())
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mapEnv(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

// request issues a request against h. A "Host" entry in headers sets
// req.Host; otherwise the host is testHost so the allowlist passes.
func request(
	t *testing.T,
	h http.Handler,
	method string,
	target string,
	headers map[string]string,
	remote string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Host = testHost

	if remote != "" {
		req.RemoteAddr = remote
	}

	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}
