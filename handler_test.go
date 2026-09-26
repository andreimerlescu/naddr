package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/andreimerlescu/naddr/ess"
)

func decodeIP(t *testing.T, body string) ipResponse {
	t.Helper()
	var resp ipResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return resp
}

func TestIPHandlerIPv4(t *testing.T) {
	h := newTestHandler(t)

	rec := request(t, h, http.MethodGet, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	want := ipResponse{
		Success:     true,
		V:           4,
		Country:     "Lithuania",
		CountryCode: "LT",
		N:           218785,
		ASN:         "AS218785",
		Description: "UAB Cherry Servers",
		Routed:      true,
		IP4:         "45.138.12.24",
		IP8:         "0.3.86.161.45.138.12.24",
		IP8ASN:      "218785.45.138.12.24",
		Range4:      "45.138.12.0/24",
		Range8:      "0.3.86.161.45.138.12.0/56",
		Range8ASN:   "218785.45.138.12.0/24",
	}
	if got := decodeIP(t, rec.Body.String()); got != want {
		t.Fatalf("response =\n%+v\nwant\n%+v", got, want)
	}

	// Schema stability: every key is always present.
	for _, key := range []string{
		`"error":null`, `"ip6":""`, `"range6":""`, `"routed":true`, `"ip8asn":`, `"range8asn":`,
	} {
		if !strings.Contains(rec.Body.String(), key) {
			t.Fatalf("body missing %s: %s", key, rec.Body.String())
		}
	}

	hdr := rec.Header()
	if hdr.Get("Cache-Control") != cacheLookup ||
		hdr.Get("Content-Type") != "application/json; charset=utf-8" ||
		hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers = %v", hdr)
	}
}

func TestIPHandlerIPv6AndNotRouted(t *testing.T) {
	h := newTestHandler(t)

	rec := request(t, h, http.MethodGet, "/ip?addr=2001:1948:e00:1001::2", nil, "")
	got := decodeIP(t, rec.Body.String())
	if rec.Code != http.StatusOK || got.V != 6 || got.IP6 != "2001:1948:e00:1001::2" ||
		got.Range6 != "2001:1948::/32" || got.IP4 != "" || got.IP8 != "" || got.Range8 != "" {
		t.Fatalf("IPv6 = %d %+v", rec.Code, got)
	}

	rec = request(t, h, http.MethodGet, "/ip?addr=100.64.0.1", nil, "")
	got = decodeIP(t, rec.Body.String())
	if rec.Code != http.StatusOK || got.CountryCode != "None" || got.Country != "Unknown" ||
		got.Routed || got.IP8 != "0.0.0.0.100.64.0.1" || got.IP8ASN != "0.100.64.0.1" {
		t.Fatalf("not routed = %d %+v", rec.Code, got)
	}
}

func TestIPHandlerIPv8(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		addr      string
		v         int
		code      string
		ip8       string
		ip8asn    string
		range8    string
		range8asn string
	}{
		// Host inside the ASN's own IPv4 range: host-level country and range.
		{"218785.45.138.12.24", 8, "LT", "0.3.86.161.45.138.12.24", "218785.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
		{"0.3.86.161.45.138.12.24", 8, "LT", "0.3.86.161.45.138.12.24", "218785.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
		// ASN-local host: ASN-level answer covering the whole ASN block.
		{"14061.10.0.0.1", 8, "US", "0.0.54.237.10.0.0.1", "14061.10.0.0.1", "0.0.54.237.0.0.0.0/32", "14061.0.0.0.0/0"},
		// r.r.r.r = 0.0.0.0 is IPv4.
		{"0.0.0.0.45.138.12.24", 4, "LT", "0.3.86.161.45.138.12.24", "218785.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
	}

	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			rec := request(t, h, http.MethodGet, "/ip?addr="+tc.addr, nil, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			got := decodeIP(t, rec.Body.String())
			if got.V != tc.v || got.CountryCode != tc.code || got.IP8 != tc.ip8 ||
				got.IP8ASN != tc.ip8asn || got.Range8 != tc.range8 || got.Range8ASN != tc.range8asn {
				t.Fatalf("got %+v", got)
			}
			if tc.v == 8 && (got.IP4 != "" || got.Range4 != "") {
				t.Fatalf("v8 result leaked IPv4 fields: %+v", got)
			}
		})
	}
}

func TestIPHandlerErrors(t *testing.T) {
	h := newTestHandler(t)

	for _, tc := range []struct {
		target string
		status int
		msg    string
	}{
		{"/ip", http.StatusBadRequest, "missing addr"},
		{"/ip?addr=bad", http.StatusBadRequest, "invalid IP address"},
		{"/ip?addr=1.2.3.4.5.6.7", http.StatusBadRequest, "invalid IP address"},
		{"/ip?addr=fe80::1%25en0", http.StatusBadRequest, "scoped IPv6"},
		{"/ip?addr=8.8.8.8", http.StatusNotFound, "address not found"},
		{"/ip?addr=99999.1.2.3.4", http.StatusNotFound, "address not found"},
	} {
		rec := request(t, h, http.MethodGet, tc.target, nil, "")
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.msg) {
			t.Fatalf("%s => %d %s", tc.target, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != cacheNever {
			t.Fatalf("%s error responses must not be cached", tc.target)
		}
	}

	rec := request(t, NewHandler(nil, defaultHandlerOptions()), http.MethodGet, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil resolver /ip = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMyHandlerProxyTrust(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		name    string
		headers map[string]string
		remote  string
		status  int
		want    string
	}{
		{"trusted X-Real-IP", map[string]string{"X-Real-IP": "45.138.12.24"}, "127.0.0.1:40000", 200, `"ip4":"45.138.12.24"`},
		{"untrusted peer cannot spoof", map[string]string{"X-Real-IP": "45.138.12.24"}, "64.23.184.179:40000", 200, `"ip4":"64.23.184.179"`},
		{"rightmost untrusted XFF hop wins", map[string]string{"X-Forwarded-For": "45.138.12.24, 64.23.184.179"}, "127.0.0.1:40000", 200, `"ip4":"64.23.184.179"`},
		{"trusted XFF hops are skipped", map[string]string{"X-Forwarded-For": "45.138.12.24, 127.0.0.1"}, "127.0.0.1:40000", 200, `"ip4":"45.138.12.24"`},
		{"XFF beats X-Real-IP", map[string]string{"X-Forwarded-For": "64.23.184.179", "X-Real-IP": "45.138.12.24"}, "127.0.0.1:40000", 200, `"ip4":"64.23.184.179"`},
		{"IPv6 loopback proxy", map[string]string{"X-Real-IP": "2001:1948::5"}, "[::1]:40000", 200, `"ip6":"2001:1948::5"`},
		{"direct local caller", nil, "127.0.0.1:40000", 400, "requester address is loopback"},
		{"malformed XFF breaks trust", map[string]string{"X-Forwarded-For": "garbage"}, "127.0.0.1:40000", 400, "requester address is loopback"},
		{"not in database", nil, "8.8.8.8:40000", 404, "address not found"},
		{"bad remote", nil, "nonsense", 400, "invalid remote address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, h, http.MethodGet, "/my", tc.headers, tc.remote)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("=> %d %s", rec.Code, rec.Body.String())
			}
		})
	}

	opts := defaultHandlerOptions()
	opts.TrustedProxies = nil
	rec := request(t, NewHandler(mustTestResolver(t), opts), http.MethodGet, "/my",
		map[string]string{"X-Real-IP": "45.138.12.24"}, "127.0.0.1:40000")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no trusted proxies must ignore headers: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIsAddrHandler(t *testing.T) {
	h := newTestHandler(t)

	for _, tc := range []struct {
		query  string
		status int
		want   []string
	}{
		{"ess=64.23.184.179&in=64.23.176.0/20", 200, []string{`"v":4`, `"member":true`, `"network":"64.23.176.0/20"`}},
		{"ess=64.23.184.179&in=/20", 200, []string{`"member":true`, `"network":"64.23.176.0/20"`}},
		{"ess=64.23.184.179&in=64.23.160.0/20", 200, []string{`"success":true`, `"member":false`}},
		{"ess=2001:1948::1&in=2001:1948::/32", 200, []string{`"v":6`, `"member":true`}},
		{"ess=218785.45.138.12.24&in=218785.45.138.12.0/24", 200, []string{`"v":8`, `"member":true`, `"network":"0.3.86.161.45.138.12.0/56"`}},
		{"ess=218785.45.138.12.24&in=14061.0.0.0.0/0", 200, []string{`"member":false`}},
		{"ess=64.23.184.179&in=2001:db8::/32", 400, []string{"families differ"}},
		{"in=/20", 400, []string{"missing ess"}},
		{"ess=64.23.184.179", 400, []string{"missing in"}},
		{"ess=bad&in=20", 400, []string{"invalid IP address"}},
	} {
		rec := request(t, h, http.MethodGet, "/is/addr?"+tc.query, nil, "")
		if rec.Code != tc.status {
			t.Fatalf("%s => %d %s", tc.query, rec.Code, rec.Body.String())
		}
		for _, w := range tc.want {
			if !strings.Contains(rec.Body.String(), w) {
				t.Fatalf("%s body missing %s: %s", tc.query, w, rec.Body.String())
			}
		}
	}
}

func TestOperationalRoutes(t *testing.T) {
	h := newTestHandler(t)

	rec := request(t, h, http.MethodGet, "/healthz", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":true`) {
		t.Fatalf("healthz = %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/readyz", nil, "")
	var ready readyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !ready.Success || ready.IPv4Ranges != 4 ||
		ready.IPv6Ranges != 1 || ready.ASNs != 4 || ready.LoadedAt == "" || ready.LastReloadError != nil {
		t.Fatalf("readyz = %d %+v", rec.Code, ready)
	}

	rec = request(t, h, http.MethodGet, "/version", nil, "")
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"version":"`+BinaryVersion()+`"`) ||
		!strings.Contains(rec.Body.String(), ess.IPv8Draft) {
		t.Fatalf("version = %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodHead, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d", rec.Code)
	}

	rec = request(t, h, http.MethodPost, "/healthz", nil, "")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST = %d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}

	rec = request(t, h, http.MethodGet, "/not-found", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404 = %d", rec.Code)
	}

	rec = request(t, NewHandler(nil, defaultHandlerOptions()), http.MethodGet, "/readyz", nil, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil readyz = %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostAllowlist(t *testing.T) {
	h := newTestHandler(t)

	for _, host := range []string{"127.0.0.1:8080", "localhost", "LOCALHOST:8080", "[::1]:8080"} {
		rec := request(t, h, http.MethodGet, "/healthz", map[string]string{"Host": host}, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("host %q = %d", host, rec.Code)
		}
	}

	rec := request(t, h, http.MethodGet, "/healthz", map[string]string{"Host": "rebind.attacker.example"}, "")
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding host = %d", rec.Code)
	}

	opts := defaultHandlerOptions()
	opts.AllowedHosts = nil
	rec = request(t, NewHandler(mustTestResolver(t), opts), http.MethodGet, "/healthz",
		map[string]string{"Host": "anything.example"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled allowlist = %d", rec.Code)
	}
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	opts := defaultHandlerOptions()
	opts.AccessLog = true
	opts.Logger = slog.New(slog.NewTextHandler(&buf, nil))

	h := NewHandler(mustTestResolver(t), opts)
	request(t, h, http.MethodGet, "/ip?addr=45.138.12.24", nil, "")

	line := buf.String()
	if !strings.Contains(line, "path=/ip") || !strings.Contains(line, "status=200") {
		t.Fatalf("access log = %q", line)
	}
	if strings.Contains(line, "45.138.12.24") {
		t.Fatalf("access log leaked query string: %q", line)
	}
}
