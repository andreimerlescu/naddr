package ess

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testTSV = `range_start	range_end	AS_number	country_code	AS_description
45.138.12.0	45.138.12.255	218785	LT	UAB Cherry Servers
64.23.176.0	64.23.191.255	14061	US	DIGITALOCEAN-ASN
64.24.0.0	64.24.0.255	14061	US	DIGITALOCEAN-ASN
100.64.0.0	100.64.0.255	0	None	Not routed
2001:1948::	2001:1948:ffff:ffff:ffff:ffff:ffff:ffff	210	US	Internet2
`

func mustTestResolver(t testing.TB) *Resolver {
	t.Helper()
	resolver, err := Load(strings.NewReader(testTSV))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return resolver
}

func request(t *testing.T, h http.Handler, method, target string, headers map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
