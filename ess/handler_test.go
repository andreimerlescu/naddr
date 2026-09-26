package ess

import (
	"net/http"
	"strings"
	"testing"
)

func TestIPHandler(t *testing.T) {
	h := NewHandler(mustTestResolver(t))

	rec := request(t, h, http.MethodGet, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`"error":null`, `"success":true`, `"v":4`, `"country":"Lithuania"`,
		`"country_code":"LT"`, `"n":218785`, `"asn":"AS218785"`,
		`"description":"UAB Cherry Servers"`, `"ip4":"45.138.12.24"`,
		`"range4":"45.138.12.0/24"`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("body missing %s: %s", want, rec.Body.String())
		}
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}

	rec = request(t, h, http.MethodGet, "/ip?addr=100.64.0.1", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"country_code":"None"`) || !strings.Contains(rec.Body.String(), `"country":"Unknown"`) {
		t.Fatalf("None response = %d %s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		target string
		status int
		msg    string
	}{
		{"/ip", http.StatusBadRequest, "missing addr"},
		{"/ip?addr=bad", http.StatusBadRequest, "invalid IP address"},
		{"/ip?addr=8.8.8.8", http.StatusNotFound, "address not found"},
	} {
		rec = request(t, h, http.MethodGet, tc.target, nil, "")
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.msg) {
			t.Fatalf("%s => %d %s", tc.target, rec.Code, rec.Body.String())
		}
	}
}

func TestMyHandlerAndProxyTrust(t *testing.T) {
	h := NewHandler(mustTestResolver(t))

	rec := request(t, h, http.MethodGet, "/my", map[string]string{"X-Real-IP": "45.138.12.24"}, "127.0.0.1:40000")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip4":"45.138.12.24"`) {
		t.Fatalf("trusted proxy response = %d %s", rec.Code, rec.Body.String())
	}

	// Non-loopback peers must not be able to spoof proxy headers.
	rec = request(t, h, http.MethodGet, "/my", map[string]string{"X-Real-IP": "45.138.12.24"}, "64.23.184.179:40000")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip4":"64.23.184.179"`) {
		t.Fatalf("untrusted proxy response = %d %s", rec.Code, rec.Body.String())
	}
}

func TestIsAddrOperationalRoutesAndMethods(t *testing.T) {
	h := NewHandler(mustTestResolver(t))

	rec := request(t, h, http.MethodGet, "/is/addr?ess=64.23.184.179&in=64.23.176.0/20", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":true`) {
		t.Fatalf("membership = %d %s", rec.Code, rec.Body.String())
	}

	for _, route := range []string{"/healthz", "/readyz"} {
		rec = request(t, h, http.MethodGet, route, nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", route, rec.Code, rec.Body.String())
		}
	}

	rec = request(t, h, http.MethodPost, "/healthz", nil, "")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("method = %d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}

	rec = request(t, h, http.MethodGet, "/not-found", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404 = %d", rec.Code)
	}

	rec = request(t, NewHandler(nil), http.MethodGet, "/readyz", nil, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil readyz = %d %s", rec.Code, rec.Body.String())
	}
}
