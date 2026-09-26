package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unsafe"
)

const testTSV = `range_start	range_end	AS_number	country_code	AS_description
45.138.12.0	45.138.12.255	218785	LT	TEST-LT
64.23.176.0	64.23.191.255	14061	US	TEST-US
2001:1948::	2001:1948:ffff:ffff:ffff:ffff:ffff:ffff	210	US	TEST-V6
`

func mustTestDB(t testing.TB) *database {
	t.Helper()
	db, err := loadDatabaseReader(strings.NewReader(testTSV))
	if err != nil {
		t.Fatalf("loadDatabaseReader: %v", err)
	}
	return db
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

func TestRangeStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(v4Range{}); got != 16 {
		t.Fatalf("v4Range size = %d, want 16", got)
	}
	if got := unsafe.Sizeof(v6Range{}); got != 40 {
		t.Fatalf("v6Range size = %d, want 40", got)
	}
}

func TestLookupIPv4AndIPv6(t *testing.T) {
	db := mustTestDB(t)

	v4 := netip.MustParseAddr("45.138.12.24")
	r4, ok := db.lookupV4(ipv4Uint32(v4))
	if !ok {
		t.Fatal("IPv4 lookup missed")
	}
	if r4.asn != 218785 || countryName(r4.country) != "Lithuania" || formatV4Range(r4) != "45.138.12.0/24" {
		t.Fatalf("unexpected IPv4 result: %+v %q %q", r4, countryName(r4.country), formatV4Range(r4))
	}

	v6 := netip.MustParseAddr("2001:1948:e00:1001::2")
	r6, ok := db.lookupV6(uint128FromAddr(v6))
	if !ok {
		t.Fatal("IPv6 lookup missed")
	}
	if r6.asn != 210 || countryName(r6.country) != "United States" || formatV6Range(r6) != "2001:1948::/32" {
		t.Fatalf("unexpected IPv6 result: %+v %q %q", r6, countryName(r6.country), formatV6Range(r6))
	}

	if _, ok := db.lookupV4(ipv4Uint32(netip.MustParseAddr("1.1.1.1"))); ok {
		t.Fatal("unexpected IPv4 hit")
	}
	if _, ok := db.lookupV4(ipv4Uint32(netip.MustParseAddr("255.255.255.255"))); ok {
		t.Fatal("unexpected IPv4 hit after final range")
	}
	if _, ok := db.lookupV6(uint128FromAddr(netip.MustParseAddr("::1"))); ok {
		t.Fatal("unexpected IPv6 hit")
	}
	if _, ok := db.lookupV6(uint128FromAddr(netip.MustParseAddr("ffff::1"))); ok {
		t.Fatal("unexpected IPv6 hit after final range")
	}
}

func TestIPHandler(t *testing.T) {
	h := newHandler(mustTestDB(t))

	rec := request(t, h, http.MethodGet, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	wantFragments := []string{
		`"error":null`,
		`"success":true`,
		`"v":4`,
		`"country":"Lithuania"`,
		`"n":218785`,
		`"asn":"AS218785"`,
		`"ip4":"45.138.12.24"`,
		`"range4":"45.138.12.0/24"`,
	}
	for _, want := range wantFragments {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("body missing %s: %s", want, rec.Body.String())
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}

	rec = request(t, h, http.MethodHead, "/ip?addr=2001:1948:e00:1001::2", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("IPv6 HEAD status = %d", rec.Code)
	}

	rec = request(t, h, http.MethodGet, "/ip?addr=2001:1948:e00:1001::2", nil, "")
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"v":6`) ||
		!strings.Contains(rec.Body.String(), `"asn":"AS210"`) ||
		!strings.Contains(rec.Body.String(), `"range6":"2001:1948::/32"`) {
		t.Fatalf("unexpected IPv6 response: %d %s", rec.Code, rec.Body.String())
	}

	cases := []struct {
		target string
		status int
		error  string
	}{
		{"/ip", http.StatusBadRequest, "missing addr"},
		{"/ip?addr=not-an-ip", http.StatusBadRequest, "invalid IP address"},
		{"/ip?addr=fe80::1%25en0", http.StatusBadRequest, "scoped IPv6 addresses are not supported"},
		{"/ip?addr=8.8.8.8", http.StatusNotFound, "address not found"},
		{"/ip?addr=2001:db8::1", http.StatusNotFound, "address not found"},
	}
	for _, tc := range cases {
		rec = request(t, h, http.MethodGet, tc.target, nil, "")
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.error) {
			t.Fatalf("%s => %d %s", tc.target, rec.Code, rec.Body.String())
		}
	}
}

func TestMyHandlerAndProxyTrust(t *testing.T) {
	h := newHandler(mustTestDB(t))

	rec := request(t, h, http.MethodGet, "/my", map[string]string{
		"X-Real-IP": "64.23.184.179",
	}, "127.0.0.1:50000")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip4":"64.23.184.179"`) {
		t.Fatalf("X-Real-IP response: %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/my", map[string]string{
		"X-Real-IP":       "bad",
		"X-Forwarded-For": "64.23.184.179, 10.0.0.1",
	}, "127.0.0.1:50000")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip4":"64.23.184.179"`) {
		t.Fatalf("X-Forwarded-For response: %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/my", map[string]string{
		"X-Real-IP":       "45.138.12.24",
		"X-Forwarded-For": "45.138.12.24",
	}, "64.23.184.179:50000")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip4":"64.23.184.179"`) {
		t.Fatalf("untrusted proxy header was honored: %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/my", nil, "bad-remote")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid remote address") {
		t.Fatalf("invalid remote response: %d %s", rec.Code, rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/my", map[string]string{
		"X-Forwarded-For": " , 64.23.184.179",
	}, "127.0.0.1")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty first forwarded address should fall back to loopback: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIsAddrHandler(t *testing.T) {
	h := newHandler(mustTestDB(t))

	cases := []struct {
		target      string
		status      int
		successJSON string
		errorPart   string
	}{
		{"/is/addr?ess=64.23.184.179&in=64.23.176.0%2F20", 200, `"success":true`, ""},
		{"/is/addr?ess=64.23.184.179&in=%2F20", 200, `"success":true`, ""},
		{"/is/addr?ess=64.23.184.179&in=20", 200, `"success":true`, ""},
		{"/is/addr?ess=64.23.184.179&in=64.23.160.0%2F20", 200, `"success":false`, ""},
		{"/is/addr?ess=2001:1948::1&in=2001:1948::%2F32", 200, `"success":true`, ""},
		{"/is/addr?in=20", 400, `"success":false`, "missing ess"},
		{"/is/addr?ess=nope&in=20", 400, `"success":false`, "invalid IP address"},
		{"/is/addr?ess=64.23.184.179", 400, `"success":false`, "missing in"},
		{"/is/addr?ess=64.23.184.179&in=%2Fnope", 400, `"success":false`, "invalid CIDR prefix length"},
		{"/is/addr?ess=64.23.184.179&in=nope", 400, `"success":false`, "in must be ip/cidr, /cidr, or cidr"},
		{"/is/addr?ess=64.23.184.179&in=33", 400, `"success":false`, "between 0 and 32"},
		{"/is/addr?ess=2001:1948::1&in=129", 400, `"success":false`, "between 0 and 128"},
		{"/is/addr?ess=64.23.184.179&in=bad%2F20", 400, `"success":false`, "invalid CIDR"},
		{"/is/addr?ess=64.23.184.179&in=2001:db8::%2F32", 400, `"success":false`, "families differ"},
	}
	for _, tc := range cases {
		rec := request(t, h, http.MethodGet, tc.target, nil, "")
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.successJSON) {
			t.Fatalf("%s => %d %s", tc.target, rec.Code, rec.Body.String())
		}
		if tc.errorPart != "" && !strings.Contains(rec.Body.String(), tc.errorPart) {
			t.Fatalf("%s missing error %q: %s", tc.target, tc.errorPart, rec.Body.String())
		}
	}
}

func TestOperationalRoutesMethodsAnd404(t *testing.T) {
	h := newHandler(mustTestDB(t))

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := request(t, h, http.MethodGet, path, nil, "")
		if rec.Code != http.StatusOK || rec.Body.String() != "{\"error\":null,\"success\":true}\n" {
			t.Fatalf("%s => %d %q", path, rec.Code, rec.Body.String())
		}
	}

	rec := request(t, h, http.MethodPost, "/ip?addr=45.138.12.24", nil, "")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST => %d allow=%q body=%s", rec.Code, rec.Header().Get("Allow"), rec.Body.String())
	}

	rec = request(t, h, http.MethodGet, "/does-not-exist", nil, "")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "route not found") {
		t.Fatalf("404 => %d %s", rec.Code, rec.Body.String())
	}
}

func TestParserValidation(t *testing.T) {
	validPrefix := "range_start\trange_end\tAS_number\tcountry_code\tAS_description\n"

	cases := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", "no address ranges"},
		{"blank-and-comment", "\n# hi\n" + validPrefix, "no address ranges"},
		{"few-columns", "1.1.1.1\n", "expected at least 5 TSV columns"},
		{"missing-end", "1.1.1.1\t\n", "missing range_end"},
		{"missing-asn", "1.1.1.1\t1.1.1.2\t\n", "missing AS_number"},
		{"missing-description", "1.1.1.1\t1.1.1.2\t1\tUS\n", "missing AS_description"},
		{"bad-start", "bad\t1.1.1.2\t1\tUS\tx\n", "invalid range_start"},
		{"bad-end", "1.1.1.1\tbad\t1\tUS\tx\n", "invalid range_end"},
		{"family", "1.1.1.1\t2001:db8::1\t1\tUS\tx\n", "address families differ"},
		{"empty-asn", "1.1.1.1\t1.1.1.2\t\tUS\tx\n", "empty integer"},
		{"bad-asn", "1.1.1.1\t1.1.1.2\t1x\tUS\tx\n", "non-decimal integer"},
		{"overflow-asn", "1.1.1.1\t1.1.1.2\t4294967296\tUS\tx\n", "exceeds uint32"},
		{"short-country", "1.1.1.1\t1.1.1.2\t1\tU\tx\n", "exactly two letters"},
		{"bad-country", "1.1.1.1\t1.1.1.2\t1\tU1\tx\n", "alphabetic"},
		{"reverse4", "1.1.1.2\t1.1.1.1\t1\tUS\tx\n", "reversed IPv4"},
		{"overlap4", "1.1.1.0\t1.1.1.10\t1\tUS\tx\n1.1.1.10\t1.1.1.20\t2\tUS\tx\n", "IPv4 ranges are unsorted or overlapping"},
		{"reverse6", "2001:db8::2\t2001:db8::1\t1\tUS\tx\n", "reversed IPv6"},
		{"overlap6", "2001:db8::\t2001:db8::10\t1\tUS\tx\n2001:db8::10\t2001:db8::20\t2\tUS\tx\n", "IPv6 ranges are unsorted or overlapping"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadDatabaseReader(strings.NewReader(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}

	db, err := loadDatabaseReader(strings.NewReader(
		"# comment\r\n" + validPrefix +
			"1.1.1.0\t1.1.1.255\t1\tus\tdesc",
	))
	if err != nil {
		t.Fatalf("valid CRLF/no-final-newline data: %v", err)
	}
	if got := countryName(db.v4[0].country); got != "United States" {
		t.Fatalf("lowercase country normalization = %q", got)
	}
}

type failingReader struct {
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("read failed")
	}
	r.done = true
	copy(p, "1.1.1.0\t1.1.1.255\t1\tUS\tdesc\n")
	return len("1.1.1.0\t1.1.1.255\t1\tUS\tdesc\n"), nil
}

func TestReaderAndFSFailures(t *testing.T) {
	if _, err := loadDatabaseReader(strings.NewReader(strings.Repeat("x", maxTSVLineBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("long line error = %v", err)
	}

	if _, err := loadDatabaseReader(&failingReader{}); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("reader error = %v", err)
	}

	if _, err := loadDatabaseFS(fstest.MapFS{}, dataPath); err == nil {
		t.Fatal("expected fs open error")
	}

	m := fstest.MapFS{
		dataPath: &fstest.MapFile{Data: []byte(testTSV)},
	}
	db, err := loadDatabaseFS(m, dataPath)
	if err != nil || len(db.v4) != 2 || len(db.v6) != 1 {
		t.Fatalf("loadDatabaseFS valid: db=%v err=%v", db, err)
	}
}

func TestPrefixAndFormattingEdges(t *testing.T) {
	if got := exactV4Prefix(0, ^uint32(0)); got != 0 {
		t.Fatalf("IPv4 /0 prefix = %d", got)
	}
	if got := exactV4Prefix(1, 2); got != 255 {
		t.Fatalf("non-CIDR IPv4 prefix = %d", got)
	}

	v4 := v4Range{start: ipv4Uint32(netip.MustParseAddr("10.0.0.1")), end: ipv4Uint32(netip.MustParseAddr("10.0.0.2")), prefix: 255}
	if got := formatV4Range(v4); got != "10.0.0.1-10.0.0.2" {
		t.Fatalf("non-CIDR IPv4 range = %q", got)
	}

	full6Start := uint128{}
	full6End := uint128{hi: ^uint64(0), lo: ^uint64(0)}
	if got := exactV6Prefix(full6Start, full6End); got != 0 {
		t.Fatalf("IPv6 /0 prefix = %d", got)
	}

	p96Start := uint128FromAddr(netip.MustParseAddr("2001:db8::"))
	p96End := uint128FromAddr(netip.MustParseAddr("2001:db8::ffff:ffff"))
	if got := exactV6Prefix(p96Start, p96End); got != 96 {
		t.Fatalf("IPv6 /96 prefix = %d", got)
	}

	unalignedHiStart := uint128FromAddr(netip.MustParseAddr("2001:db9::"))
	unalignedHiEnd := uint128FromAddr(netip.MustParseAddr("2001:dbf:ffff:ffff:ffff:ffff:ffff:ffff"))
	if got := exactV6Prefix(unalignedHiStart, unalignedHiEnd); got != 255 {
		t.Fatalf("unaligned high-half IPv6 range = %d", got)
	}

	badEndStart := uint128FromAddr(netip.MustParseAddr("2001:db8::"))
	badEnd := uint128FromAddr(netip.MustParseAddr("2001:db8:7fff::"))
	if got := exactV6Prefix(badEndStart, badEnd); got != 255 {
		t.Fatalf("incomplete high-half IPv6 range = %d", got)
	}

	start := uint128FromAddr(netip.MustParseAddr("2001:db8::1"))
	end := uint128FromAddr(netip.MustParseAddr("2001:db8::2"))
	if got := exactV6Prefix(start, end); got != 255 {
		t.Fatalf("non-CIDR IPv6 prefix = %d", got)
	}
	v6 := v6Range{start: start, end: end, prefix: 255}
	if got := formatV6Range(v6); got != "2001:db8::1-2001:db8::2" {
		t.Fatalf("non-CIDR IPv6 range = %q", got)
	}

	if compare128(uint128{hi: 1}, uint128{hi: 2}) >= 0 ||
		compare128(uint128{hi: 2}, uint128{hi: 1}) <= 0 ||
		compare128(uint128{hi: 1, lo: 1}, uint128{hi: 1, lo: 2}) >= 0 ||
		compare128(uint128{hi: 1, lo: 2}, uint128{hi: 1, lo: 1}) <= 0 ||
		compare128(uint128{hi: 1, lo: 1}, uint128{hi: 1, lo: 1}) != 0 {
		t.Fatal("compare128 ordering failed")
	}

	if got := countryName(0x5151); got != "Unknown" {
		t.Fatalf("unknown country = %q", got)
	}
}

func TestRun(t *testing.T) {
	oldRun := runApplication
	oldExit := exitProcess
	defer func() {
		runApplication = oldRun
		exitProcess = oldExit
	}()

	exitCode := 0
	exitProcess = func(code int) { exitCode = code }

	runApplication = func() error { return nil }
	run()
	if exitCode != 0 {
		t.Fatalf("unexpected exit code %d", exitCode)
	}

	runApplication = func() error { return errors.New("boom") }
	run()
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
}

func TestMainAndDefaultListenTCP(t *testing.T) {
	oldRun := runApplication
	oldExit := exitProcess
	defer func() {
		runApplication = oldRun
		exitProcess = oldExit
	}()

	runApplication = func() error { return nil }
	exitProcess = func(int) { t.Fatal("main unexpectedly exited") }
	main()

	ln, err := listenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("default listenTCP: %v", err)
	}
	_ = ln.Close()
}

func TestRunServer(t *testing.T) {
	oldFS := applicationFS
	oldListen := listenTCP
	oldNotify := notifyContext
	oldGetenv := getenv
	defer func() {
		applicationFS = oldFS
		listenTCP = oldListen
		notifyContext = oldNotify
		getenv = oldGetenv
	}()

	applicationFS = fstest.MapFS{
		dataPath: &fstest.MapFile{Data: []byte(testTSV)},
	}
	getenv = func(string) string { return "" }

	listenTCP = func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != defaultListenAddr {
			t.Fatalf("listen args: %q %q", network, address)
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}
	notifyContext = func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}

	if err := runServer(); err != nil {
		t.Fatalf("runServer canceled startup: %v", err)
	}

	getenv = func(string) string { return "127.0.0.1:9999" }
	listenTCP = func(network, address string) (net.Listener, error) {
		if address != "127.0.0.1:9999" {
			t.Fatalf("env listen address = %q", address)
		}
		return nil, errors.New("listen failed")
	}
	if err := runServer(); err == nil || !strings.Contains(err.Error(), "listen failed") {
		t.Fatalf("listen error = %v", err)
	}

	applicationFS = fstest.MapFS{}
	if err := runServer(); err == nil || !strings.Contains(err.Error(), "load embedded database") {
		t.Fatalf("load error = %v", err)
	}
}

type errorListener struct {
	err error
}

func (l errorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errorListener) Close() error              { return nil }
func (l errorListener) Addr() net.Addr            { return dummyAddr("error-listener") }

type dummyAddr string

func (a dummyAddr) Network() string { return "test" }
func (a dummyAddr) String() string  { return string(a) }

func TestServeUntilDoneErrorsAndShutdown(t *testing.T) {
	srv := newHTTPServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	want := errors.New("accept failed")
	if err := serveUntilDone(context.Background(), srv, errorListener{err: want}); !errors.Is(err, want) {
		t.Fatalf("serve error = %v, want %v", err, want)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv = newHTTPServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := serveUntilDone(ctx, srv, ln); err != nil {
		t.Fatalf("graceful shutdown = %v", err)
	}

	// Force Shutdown to hit its deadline while a request is active. serveUntilDone
	// must then Close the server and return the shutdown error.
	oldTimeout := gracefulShutdownTimeout
	gracefulShutdownTimeout = time.Millisecond
	defer func() { gracefulShutdownTimeout = oldTimeout }()

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	blocking := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	srv = newHTTPServer("", blocking)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_, _ = http.Get("http://" + ln.Addr().String())
	}()
	serveCtx, serveCancel := context.WithCancel(context.Background())
	go func() {
		<-started
		serveCancel()
	}()
	if err := serveUntilDone(serveCtx, srv, ln); err == nil {
		t.Fatal("expected graceful shutdown deadline error")
	}
	<-requestDone

	// A server already marked closed returns http.ErrServerClosed directly.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv = newHTTPServer("", http.NotFoundHandler())
	_ = srv.Close()
	if err := serveUntilDone(context.Background(), srv, ln); err != nil {
		t.Fatalf("pre-closed server = %v", err)
	}
}

func TestHTTP2Cleartext(t *testing.T) {
	db := mustTestDB(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := newHTTPServer(ln.Addr().String(), newHandler(db))
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		<-errc
	}()

	tr := &http.Transport{}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)
	client := &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}

	resp, err := client.Get("http://" + ln.Addr().String() + "/ip?addr=45.138.12.24")
	if err != nil {
		t.Fatalf("HTTP/2 request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.ProtoMajor != 2 {
		t.Fatalf("protocol = %q, want HTTP/2", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s", resp.Status)
	}
}

func TestNewHTTPServerConfiguration(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:1", http.NotFoundHandler())
	if srv.Addr != "127.0.0.1:1" ||
		srv.ReadHeaderTimeout != 2*time.Second ||
		srv.WriteTimeout != 5*time.Second ||
		srv.IdleTimeout != 60*time.Second ||
		srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("unexpected server configuration: %+v", srv)
	}
	if srv.Protocols == nil || !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols = %v", srv.Protocols)
	}
}

func TestLookupAllocations(t *testing.T) {
	db := mustTestDB(t)
	v4 := ipv4Uint32(netip.MustParseAddr("64.23.184.179"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := db.lookupV4(v4); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv4 lookup allocations = %f, want 0", allocs)
	}

	v6 := uint128FromAddr(netip.MustParseAddr("2001:1948:e00:1001::2"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := db.lookupV6(v6); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv6 lookup allocations = %f, want 0", allocs)
	}
}

func BenchmarkLookupIPv4(b *testing.B) {
	db, err := loadDatabaseFS(dataFS, dataPath)
	if err != nil {
		b.Fatal(err)
	}
	if len(db.v4) == 0 {
		b.Fatal("no IPv4 ranges")
	}
	target := db.v4[len(db.v4)/2].start

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := db.lookupV4(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

func BenchmarkLookupIPv6(b *testing.B) {
	db, err := loadDatabaseFS(dataFS, dataPath)
	if err != nil {
		b.Fatal(err)
	}
	if len(db.v6) == 0 {
		b.Fatal("no IPv6 ranges")
	}
	target := db.v6[len(db.v6)/2].start

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := db.lookupV6(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

func BenchmarkHTTPIP(b *testing.B) {
	db, err := loadDatabaseFS(dataFS, dataPath)
	if err != nil {
		b.Fatal(err)
	}
	if len(db.v4) == 0 {
		b.Fatal("no IPv4 ranges")
	}
	addr := ipv4Addr(db.v4[len(db.v4)/2].start).String()
	h := newHandler(db)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ip?addr="+addr, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatal(rec.Code)
		}
	}
}

func BenchmarkLoadEmbeddedDatabase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		b.StartTimer()
		db, err := loadDatabaseFS(dataFS, dataPath)
		if err != nil {
			b.Fatal(err)
		}
		if len(db.v4)+len(db.v6) == 0 {
			b.Fatal("empty database")
		}
	}
}

func FuzzParseAndLookup(f *testing.F) {
	db, err := loadDatabaseReader(strings.NewReader(testTSV))
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"45.138.12.24",
		"64.23.184.179",
		"2001:1948:e00:1001::2",
		"::ffff:45.138.12.24",
		"bad",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, s string) {
		addr, err := parseRequestAddr(s)
		if err != nil {
			return
		}
		if addr.Is4() {
			_, _ = db.lookupV4(ipv4Uint32(addr))
			return
		}
		_, _ = db.lookupV6(uint128FromAddr(addr))
	})
}

func FuzzCIDRMembership(f *testing.F) {
	seeds := [][2]string{
		{"64.23.184.179", "64.23.176.0/20"},
		{"64.23.184.179", "/20"},
		{"64.23.184.179", "20"},
		{"2001:1948::1", "2001:1948::/32"},
		{"bad", "20"},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, addrText, spec string) {
		addr, err := parseRequestAddr(addrText)
		if err != nil {
			return
		}
		prefix, err := parseMembershipPrefix(addr, spec)
		if err != nil {
			return
		}
		_ = prefix.Contains(addr)
	})
}

func FuzzTSVParser(f *testing.F) {
	f.Add(testTSV)
	f.Add("1.1.1.0\t1.1.1.255\t13335\tUS\towner\n")
	f.Add("bad")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxTSVLineBytes*2 {
			t.Skip()
		}
		_, _ = loadDatabaseReader(strings.NewReader(input))
	})
}

// Ensure the fs import remains exercised by compile-time interface assertions.
var _ fs.FS = fstest.MapFS{}
