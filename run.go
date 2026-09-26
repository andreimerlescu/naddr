package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	dataPath          = "tsv/ip2asn-combined.tsv"
	defaultListenAddr = "127.0.0.1:8080"

	v4CapacityHint = 540_000
	v6CapacityHint = 185_000

	maxTSVLineBytes = 64 << 10
)

var gracefulShutdownTimeout = 5 * time.Second

// dataFS is embedded into the executable at build time.
//
//go:embed tsv/ip2asn-combined.tsv
var dataFS embed.FS

// These private indirections keep operating-system edges testable without
// changing the production API or adding test-only behavior.
var (
	applicationFS fs.FS = dataFS

	listenTCP = func(network, address string) (net.Listener, error) {
		return net.Listen(network, address)
	}

	notifyContext  = signal.NotifyContext
	getenv         = os.Getenv
	exitProcess    = os.Exit
	runApplication = runServer
)

// run is intentionally the only function called by main().
func run() {
	if err := runApplication(); err != nil {
		slog.Error("naddr stopped", "error", err)
		exitProcess(1)
	}
}

type database struct {
	v4 []v4Range
	v6 []v6Range
}

type v4Range struct {
	start   uint32
	end     uint32
	asn     uint32
	country uint16
	prefix  uint8
	_       uint8
}

type uint128 struct {
	hi uint64
	lo uint64
}

type v6Range struct {
	start   uint128
	end     uint128
	asn     uint32
	country uint16
	prefix  uint8
	_       uint8
}

type ipResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
	V       int     `json:"v"`
	Country string  `json:"country"`
	N       uint32  `json:"n"`
	ASN     string  `json:"asn"`
	IP4     string  `json:"ip4"`
	IP6     string  `json:"ip6"`
	IP8     string  `json:"ip8"`
	Range4  string  `json:"range4"`
	Range6  string  `json:"range6"`
	Range8  string  `json:"range8"`
}

type boolResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
}

func runServer() error {
	db, err := loadDatabaseFS(applicationFS, dataPath)
	if err != nil {
		return fmt.Errorf("load embedded database: %w", err)
	}

	addr := strings.TrimSpace(getenv("NADDR_LISTEN"))
	if addr == "" {
		addr = defaultListenAddr
	}

	ln, err := listenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := newHTTPServer(addr, newHandler(db))

	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info(
		"naddr ready",
		"listen", ln.Addr().String(),
		"ipv4_ranges", len(db.v4),
		"ipv6_ranges", len(db.v6),
	)

	return serveUntilDone(ctx, srv, ln)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
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

func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener) error {
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
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

func loadDatabaseFS(source fs.FS, path string) (*database, error) {
	f, err := source.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return loadDatabaseReader(f)
}

func loadDatabaseReader(r io.Reader) (*database, error) {
	db := &database{
		v4: make([]v4Range, 0, v4CapacityHint),
		v6: make([]v6Range, 0, v6CapacityHint),
	}

	br := bufio.NewReaderSize(r, maxTSVLineBytes)
	lineNo := 0

	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("TSV line exceeds %d bytes", maxTSVLineBytes)
		}

		if len(line) > 0 {
			lineNo++
			if parseErr := db.parseLine(line, lineNo); parseErr != nil {
				return nil, parseErr
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	if len(db.v4) == 0 && len(db.v6) == 0 {
		return nil, errors.New("TSV contained no address ranges")
	}

	return db, nil
}

func (db *database) parseLine(line []byte, lineNo int) error {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})

	if len(line) == 0 || line[0] == '#' {
		return nil
	}

	startField, rest, ok := cutTab(line)
	if !ok {
		return fmt.Errorf("line %d: expected at least 5 TSV columns", lineNo)
	}
	endField, rest, ok := cutTab(rest)
	if !ok {
		return fmt.Errorf("line %d: missing range_end", lineNo)
	}
	asnField, rest, ok := cutTab(rest)
	if !ok {
		return fmt.Errorf("line %d: missing AS_number", lineNo)
	}
	countryField, _, ok := cutTab(rest)
	if !ok {
		return fmt.Errorf("line %d: missing AS_description column", lineNo)
	}

	if bytes.Equal(startField, []byte("range_start")) {
		return nil
	}

	start, err := netip.ParseAddr(string(startField))
	if err != nil {
		return fmt.Errorf("line %d: invalid range_start: %w", lineNo, err)
	}
	end, err := netip.ParseAddr(string(endField))
	if err != nil {
		return fmt.Errorf("line %d: invalid range_end: %w", lineNo, err)
	}

	start = start.Unmap()
	end = end.Unmap()

	if start.Is4() != end.Is4() {
		return fmt.Errorf("line %d: address families differ", lineNo)
	}

	asn, err := parseUint32(asnField)
	if err != nil {
		return fmt.Errorf("line %d: invalid AS_number: %w", lineNo, err)
	}

	country, err := parseCountryCode(countryField)
	if err != nil {
		return fmt.Errorf("line %d: invalid country_code: %w", lineNo, err)
	}

	if start.Is4() {
		s := ipv4Uint32(start)
		e := ipv4Uint32(end)
		if s > e {
			return fmt.Errorf("line %d: reversed IPv4 range", lineNo)
		}
		if n := len(db.v4); n > 0 && s <= db.v4[n-1].end {
			return fmt.Errorf("line %d: IPv4 ranges are unsorted or overlapping", lineNo)
		}

		db.v4 = append(db.v4, v4Range{
			start:   s,
			end:     e,
			asn:     asn,
			country: country,
			prefix:  exactV4Prefix(s, e),
		})
		return nil
	}

	s := uint128FromAddr(start)
	e := uint128FromAddr(end)
	if compare128(s, e) > 0 {
		return fmt.Errorf("line %d: reversed IPv6 range", lineNo)
	}
	if n := len(db.v6); n > 0 && compare128(s, db.v6[n-1].end) <= 0 {
		return fmt.Errorf("line %d: IPv6 ranges are unsorted or overlapping", lineNo)
	}

	db.v6 = append(db.v6, v6Range{
		start:   s,
		end:     e,
		asn:     asn,
		country: country,
		prefix:  exactV6Prefix(s, e),
	})
	return nil
}

func cutTab(b []byte) (head, tail []byte, ok bool) {
	i := bytes.IndexByte(b, '\t')
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+1:], true
}

func parseUint32(b []byte) (uint32, error) {
	if len(b) == 0 {
		return 0, errors.New("empty integer")
	}

	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, errors.New("non-decimal integer")
		}
		n = n*10 + uint64(c-'0')
		if n > uint64(^uint32(0)) {
			return 0, errors.New("integer exceeds uint32")
		}
	}
	return uint32(n), nil
}

func parseCountryCode(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, errors.New("country code must contain exactly two letters")
	}

	a, z := b[0], b[1]
	if a >= 'a' && a <= 'z' {
		a -= 'a' - 'A'
	}
	if z >= 'a' && z <= 'z' {
		z -= 'a' - 'A'
	}
	if a < 'A' || a > 'Z' || z < 'A' || z > 'Z' {
		return 0, errors.New("country code must be alphabetic")
	}

	return uint16(a)<<8 | uint16(z), nil
}

func ipv4Uint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func uint128FromAddr(addr netip.Addr) uint128 {
	a := addr.As16()
	return uint128{
		hi: binary.BigEndian.Uint64(a[:8]),
		lo: binary.BigEndian.Uint64(a[8:]),
	}
}

func (u uint128) addr() netip.Addr {
	var a [16]byte
	binary.BigEndian.PutUint64(a[:8], u.hi)
	binary.BigEndian.PutUint64(a[8:], u.lo)
	return netip.AddrFrom16(a)
}

func compare128(a, b uint128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	default:
		return 0
	}
}

func exactV4Prefix(start, end uint32) uint8 {
	prefix := bits.LeadingZeros32(start ^ end)
	mask := ^uint32(0) << uint(32-prefix)
	if start&^mask != 0 || end != start|^mask {
		return 255
	}
	return uint8(prefix)
}

func exactV6Prefix(start, end uint128) uint8 {
	var prefix int
	if x := start.hi ^ end.hi; x != 0 {
		prefix = bits.LeadingZeros64(x)
	} else {
		prefix = 64 + bits.LeadingZeros64(start.lo^end.lo)
	}

	if prefix <= 64 {
		maskHi := ^uint64(0) << uint(64-prefix)
		if start.hi&^maskHi != 0 || start.lo != 0 {
			return 255
		}
		if end.hi != start.hi|^maskHi || end.lo != ^uint64(0) {
			return 255
		}
		return uint8(prefix)
	}

	lowBits := prefix - 64
	maskLo := ^uint64(0) << uint(64-lowBits)
	if start.lo&^maskLo != 0 {
		return 255
	}
	if end.hi != start.hi || end.lo != start.lo|^maskLo {
		return 255
	}
	return uint8(prefix)
}

func (db *database) lookupV4(addr uint32) (v4Range, bool) {
	lo, hi := 0, len(db.v4)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if db.v4[mid].start <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return v4Range{}, false
	}
	r := db.v4[lo-1]
	return r, addr <= r.end
}

func (db *database) lookupV6(addr uint128) (v6Range, bool) {
	lo, hi := 0, len(db.v6)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if compare128(db.v6[mid].start, addr) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return v6Range{}, false
	}
	r := db.v6[lo-1]
	return r, compare128(addr, r.end) <= 0
}

func newHandler(db *database) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/ip", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addrText := strings.TrimSpace(r.URL.Query().Get("addr"))
		if addrText == "" {
			writeIPError(w, http.StatusBadRequest, "missing addr")
			return
		}

		addr, err := parseRequestAddr(addrText)
		if err != nil {
			writeIPError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeLookup(w, db, addr, "public, max-age=3600")
	}))

	mux.HandleFunc("/my", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addr, err := requesterAddr(r)
		if err != nil {
			writeIPError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeLookup(w, db, addr, "no-store")
	}))

	mux.HandleFunc("/is/addr", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addrText := strings.TrimSpace(r.URL.Query().Get("ess"))
		if addrText == "" {
			writeBoolError(w, http.StatusBadRequest, "missing ess")
			return
		}

		addr, err := parseRequestAddr(addrText)
		if err != nil {
			writeBoolError(w, http.StatusBadRequest, err.Error())
			return
		}

		prefix, err := parseMembershipPrefix(addr, strings.TrimSpace(r.URL.Query().Get("in")))
		if err != nil {
			writeBoolError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, "no-store", boolResponse{
			Error:   nil,
			Success: prefix.Contains(addr),
		})
	}))

	mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "no-store", boolResponse{Success: true})
	}))

	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "no-store", boolResponse{Success: true})
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeBoolError(w, http.StatusNotFound, "route not found")
	})

	return mux
}

func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeBoolError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next(w, r)
	}
}

func parseRequestAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errors.New("invalid IP address")
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errors.New("scoped IPv6 addresses are not supported")
	}
	return addr.Unmap(), nil
}

func parseMembershipPrefix(addr netip.Addr, spec string) (netip.Prefix, error) {
	if spec == "" {
		return netip.Prefix{}, errors.New("missing in")
	}

	if strings.HasPrefix(spec, "/") {
		bitsN, err := strconv.Atoi(strings.TrimPrefix(spec, "/"))
		if err != nil {
			return netip.Prefix{}, errors.New("invalid CIDR prefix length")
		}
		return prefixFromBits(addr, bitsN)
	}

	if !strings.Contains(spec, "/") {
		bitsN, err := strconv.Atoi(spec)
		if err != nil {
			return netip.Prefix{}, errors.New("in must be ip/cidr, /cidr, or cidr")
		}
		return prefixFromBits(addr, bitsN)
	}

	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return netip.Prefix{}, errors.New("invalid CIDR")
	}
	if prefix.Addr().Unmap().Is4() != addr.Is4() {
		return netip.Prefix{}, errors.New("IP and CIDR address families differ")
	}
	return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked(), nil
}

func prefixFromBits(addr netip.Addr, n int) (netip.Prefix, error) {
	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	}
	if n < 0 || n > maxBits {
		return netip.Prefix{}, fmt.Errorf("CIDR prefix length must be between 0 and %d", maxBits)
	}
	return netip.PrefixFrom(addr, n).Masked(), nil
}

func requesterAddr(r *http.Request) (netip.Addr, error) {
	remoteText := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteText = host
	}
	remoteText = strings.Trim(remoteText, "[]")

	remote, err := parseRequestAddr(remoteText)
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}

	// Proxy headers are trusted only from loopback peers. The default service
	// binds to 127.0.0.1, so a local reverse proxy can safely provide /my.
	if !remote.IsLoopback() {
		return remote, nil
	}

	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if addr, err := parseRequestAddr(realIP); err == nil {
			return addr, nil
		}
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first, _, _ := strings.Cut(forwarded, ","); strings.TrimSpace(first) != "" {
			if addr, err := parseRequestAddr(strings.TrimSpace(first)); err == nil {
				return addr, nil
			}
		}
	}

	return remote, nil
}

func writeLookup(w http.ResponseWriter, db *database, addr netip.Addr, cacheControl string) {
	if addr.Is4() {
		raw := ipv4Uint32(addr)
		r, ok := db.lookupV4(raw)
		if !ok {
			writeIPError(w, http.StatusNotFound, "address not found")
			return
		}

		writeJSON(w, http.StatusOK, cacheControl, ipResponse{
			Error:   nil,
			Success: true,
			V:       4,
			Country: countryName(r.country),
			N:       r.asn,
			ASN:     "AS" + strconv.FormatUint(uint64(r.asn), 10),
			IP4:     addr.String(),
			Range4:  formatV4Range(r),
		})
		return
	}

	raw := uint128FromAddr(addr)
	r, ok := db.lookupV6(raw)
	if !ok {
		writeIPError(w, http.StatusNotFound, "address not found")
		return
	}

	writeJSON(w, http.StatusOK, cacheControl, ipResponse{
		Error:   nil,
		Success: true,
		V:       6,
		Country: countryName(r.country),
		N:       r.asn,
		ASN:     "AS" + strconv.FormatUint(uint64(r.asn), 10),
		IP6:     addr.String(),
		Range6:  formatV6Range(r),
	})
}

func formatV4Range(r v4Range) string {
	start := ipv4Addr(r.start)
	if r.prefix != 255 {
		return start.String() + "/" + strconv.Itoa(int(r.prefix))
	}
	return start.String() + "-" + ipv4Addr(r.end).String()
}

func formatV6Range(r v6Range) string {
	if r.prefix != 255 {
		return r.start.addr().String() + "/" + strconv.Itoa(int(r.prefix))
	}
	return r.start.addr().String() + "-" + r.end.addr().String()
}

func ipv4Addr(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

func writeIPError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, "no-store", ipResponse{
		Error:   stringPtr(message),
		Success: false,
	})
}

func writeBoolError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, "no-store", boolResponse{
		Error:   stringPtr(message),
		Success: false,
	})
}

func stringPtr(s string) *string {
	return &s
}

func writeJSON(w http.ResponseWriter, status int, cacheControl string, value any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", cacheControl)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func countryName(code uint16) string {
	if name, ok := countryNames[code]; ok {
		return name
	}
	return "Unknown"
}

var countryNames = map[uint16]string{
	0x4144: "Andorra",                                      // AD
	0x4145: "United Arab Emirates",                         // AE
	0x4146: "Afghanistan",                                  // AF
	0x4147: "Antigua and Barbuda",                          // AG
	0x4149: "Anguilla",                                     // AI
	0x414C: "Albania",                                      // AL
	0x414D: "Armenia",                                      // AM
	0x414F: "Angola",                                       // AO
	0x4151: "Antarctica",                                   // AQ
	0x4152: "Argentina",                                    // AR
	0x4153: "American Samoa",                               // AS
	0x4154: "Austria",                                      // AT
	0x4155: "Australia",                                    // AU
	0x4157: "Aruba",                                        // AW
	0x4158: "\u00c5land Islands",                           // AX
	0x415A: "Azerbaijan",                                   // AZ
	0x4241: "Bosnia and Herzegovina",                       // BA
	0x4242: "Barbados",                                     // BB
	0x4244: "Bangladesh",                                   // BD
	0x4245: "Belgium",                                      // BE
	0x4246: "Burkina Faso",                                 // BF
	0x4247: "Bulgaria",                                     // BG
	0x4248: "Bahrain",                                      // BH
	0x4249: "Burundi",                                      // BI
	0x424A: "Benin",                                        // BJ
	0x424C: "Saint Barth\u00e9lemy",                        // BL
	0x424D: "Bermuda",                                      // BM
	0x424E: "Brunei",                                       // BN
	0x424F: "Bolivia",                                      // BO
	0x4251: "Bonaire, Sint Eustatius and Saba",             // BQ
	0x4252: "Brazil",                                       // BR
	0x4253: "Bahamas",                                      // BS
	0x4254: "Bhutan",                                       // BT
	0x4256: "Bouvet Island",                                // BV
	0x4257: "Botswana",                                     // BW
	0x4259: "Belarus",                                      // BY
	0x425A: "Belize",                                       // BZ
	0x4341: "Canada",                                       // CA
	0x4343: "Cocos (Keeling) Islands",                      // CC
	0x4344: "DR Congo",                                     // CD
	0x4346: "Central African Republic",                     // CF
	0x4347: "Congo",                                        // CG
	0x4348: "Switzerland",                                  // CH
	0x4349: "C\u00f4te d'Ivoire",                           // CI
	0x434B: "Cook Islands",                                 // CK
	0x434C: "Chile",                                        // CL
	0x434D: "Cameroon",                                     // CM
	0x434E: "China",                                        // CN
	0x434F: "Colombia",                                     // CO
	0x4352: "Costa Rica",                                   // CR
	0x4355: "Cuba",                                         // CU
	0x4356: "Cabo Verde",                                   // CV
	0x4357: "Cura\u00e7ao",                                 // CW
	0x4358: "Christmas Island",                             // CX
	0x4359: "Cyprus",                                       // CY
	0x435A: "Czechia",                                      // CZ
	0x4445: "Germany",                                      // DE
	0x444A: "Djibouti",                                     // DJ
	0x444B: "Denmark",                                      // DK
	0x444D: "Dominica",                                     // DM
	0x444F: "Dominican Republic",                           // DO
	0x445A: "Algeria",                                      // DZ
	0x4543: "Ecuador",                                      // EC
	0x4545: "Estonia",                                      // EE
	0x4547: "Egypt",                                        // EG
	0x4548: "Western Sahara",                               // EH
	0x4552: "Eritrea",                                      // ER
	0x4553: "Spain",                                        // ES
	0x4554: "Ethiopia",                                     // ET
	0x4649: "Finland",                                      // FI
	0x464A: "Fiji",                                         // FJ
	0x464B: "Falkland Islands (Malvinas)",                  // FK
	0x464D: "Micronesia, Federated States of",              // FM
	0x464F: "Faroe Islands",                                // FO
	0x4652: "France",                                       // FR
	0x4741: "Gabon",                                        // GA
	0x4742: "United Kingdom",                               // GB
	0x4744: "Grenada",                                      // GD
	0x4745: "Georgia",                                      // GE
	0x4746: "French Guiana",                                // GF
	0x4747: "Guernsey",                                     // GG
	0x4748: "Ghana",                                        // GH
	0x4749: "Gibraltar",                                    // GI
	0x474C: "Greenland",                                    // GL
	0x474D: "Gambia",                                       // GM
	0x474E: "Guinea",                                       // GN
	0x4750: "Guadeloupe",                                   // GP
	0x4751: "Equatorial Guinea",                            // GQ
	0x4752: "Greece",                                       // GR
	0x4753: "South Georgia and the South Sandwich Islands", // GS
	0x4754: "Guatemala",                                    // GT
	0x4755: "Guam",                                         // GU
	0x4757: "Guinea-Bissau",                                // GW
	0x4759: "Guyana",                                       // GY
	0x484B: "Hong Kong",                                    // HK
	0x484D: "Heard Island and McDonald Islands",            // HM
	0x484E: "Honduras",                                     // HN
	0x4852: "Croatia",                                      // HR
	0x4854: "Haiti",                                        // HT
	0x4855: "Hungary",                                      // HU
	0x4944: "Indonesia",                                    // ID
	0x4945: "Ireland",                                      // IE
	0x494C: "Israel",                                       // IL
	0x494D: "Isle of Man",                                  // IM
	0x494E: "India",                                        // IN
	0x494F: "British Indian Ocean Territory",               // IO
	0x4951: "Iraq",                                         // IQ
	0x4952: "Iran",                                         // IR
	0x4953: "Iceland",                                      // IS
	0x4954: "Italy",                                        // IT
	0x4A45: "Jersey",                                       // JE
	0x4A4D: "Jamaica",                                      // JM
	0x4A4F: "Jordan",                                       // JO
	0x4A50: "Japan",                                        // JP
	0x4B45: "Kenya",                                        // KE
	0x4B47: "Kyrgyzstan",                                   // KG
	0x4B48: "Cambodia",                                     // KH
	0x4B49: "Kiribati",                                     // KI
	0x4B4D: "Comoros",                                      // KM
	0x4B4E: "Saint Kitts and Nevis",                        // KN
	0x4B50: "North Korea",                                  // KP
	0x4B52: "South Korea",                                  // KR
	0x4B57: "Kuwait",                                       // KW
	0x4B59: "Cayman Islands",                               // KY
	0x4B5A: "Kazakhstan",                                   // KZ
	0x4C41: "Laos",                                         // LA
	0x4C42: "Lebanon",                                      // LB
	0x4C43: "Saint Lucia",                                  // LC
	0x4C49: "Liechtenstein",                                // LI
	0x4C4B: "Sri Lanka",                                    // LK
	0x4C52: "Liberia",                                      // LR
	0x4C53: "Lesotho",                                      // LS
	0x4C54: "Lithuania",                                    // LT
	0x4C55: "Luxembourg",                                   // LU
	0x4C56: "Latvia",                                       // LV
	0x4C59: "Libya",                                        // LY
	0x4D41: "Morocco",                                      // MA
	0x4D43: "Monaco",                                       // MC
	0x4D44: "Moldova",                                      // MD
	0x4D45: "Montenegro",                                   // ME
	0x4D46: "Saint Martin (French part)",                   // MF
	0x4D47: "Madagascar",                                   // MG
	0x4D48: "Marshall Islands",                             // MH
	0x4D4B: "North Macedonia",                              // MK
	0x4D4C: "Mali",                                         // ML
	0x4D4D: "Myanmar",                                      // MM
	0x4D4E: "Mongolia",                                     // MN
	0x4D4F: "Macao",                                        // MO
	0x4D50: "Northern Mariana Islands",                     // MP
	0x4D51: "Martinique",                                   // MQ
	0x4D52: "Mauritania",                                   // MR
	0x4D53: "Montserrat",                                   // MS
	0x4D54: "Malta",                                        // MT
	0x4D55: "Mauritius",                                    // MU
	0x4D56: "Maldives",                                     // MV
	0x4D57: "Malawi",                                       // MW
	0x4D58: "Mexico",                                       // MX
	0x4D59: "Malaysia",                                     // MY
	0x4D5A: "Mozambique",                                   // MZ
	0x4E41: "Namibia",                                      // NA
	0x4E43: "New Caledonia",                                // NC
	0x4E45: "Niger",                                        // NE
	0x4E46: "Norfolk Island",                               // NF
	0x4E47: "Nigeria",                                      // NG
	0x4E49: "Nicaragua",                                    // NI
	0x4E4C: "Netherlands",                                  // NL
	0x4E4F: "Norway",                                       // NO
	0x4E50: "Nepal",                                        // NP
	0x4E52: "Nauru",                                        // NR
	0x4E55: "Niue",                                         // NU
	0x4E5A: "New Zealand",                                  // NZ
	0x4F4D: "Oman",                                         // OM
	0x5041: "Panama",                                       // PA
	0x5045: "Peru",                                         // PE
	0x5046: "French Polynesia",                             // PF
	0x5047: "Papua New Guinea",                             // PG
	0x5048: "Philippines",                                  // PH
	0x504B: "Pakistan",                                     // PK
	0x504C: "Poland",                                       // PL
	0x504D: "Saint Pierre and Miquelon",                    // PM
	0x504E: "Pitcairn",                                     // PN
	0x5052: "Puerto Rico",                                  // PR
	0x5053: "Palestine",                                    // PS
	0x5054: "Portugal",                                     // PT
	0x5057: "Palau",                                        // PW
	0x5059: "Paraguay",                                     // PY
	0x5141: "Qatar",                                        // QA
	0x5245: "R\u00e9union",                                 // RE
	0x524F: "Romania",                                      // RO
	0x5253: "Serbia",                                       // RS
	0x5255: "Russia",                                       // RU
	0x5257: "Rwanda",                                       // RW
	0x5341: "Saudi Arabia",                                 // SA
	0x5342: "Solomon Islands",                              // SB
	0x5343: "Seychelles",                                   // SC
	0x5344: "Sudan",                                        // SD
	0x5345: "Sweden",                                       // SE
	0x5347: "Singapore",                                    // SG
	0x5348: "Saint Helena, Ascension and Tristan da Cunha", // SH
	0x5349: "Slovenia",                                     // SI
	0x534A: "Svalbard and Jan Mayen",                       // SJ
	0x534B: "Slovakia",                                     // SK
	0x534C: "Sierra Leone",                                 // SL
	0x534D: "San Marino",                                   // SM
	0x534E: "Senegal",                                      // SN
	0x534F: "Somalia",                                      // SO
	0x5352: "Suriname",                                     // SR
	0x5353: "South Sudan",                                  // SS
	0x5354: "Sao Tome and Principe",                        // ST
	0x5356: "El Salvador",                                  // SV
	0x5358: "Sint Maarten (Dutch part)",                    // SX
	0x5359: "Syria",                                        // SY
	0x535A: "Eswatini",                                     // SZ
	0x5443: "Turks and Caicos Islands",                     // TC
	0x5444: "Chad",                                         // TD
	0x5446: "French Southern Territories",                  // TF
	0x5447: "Togo",                                         // TG
	0x5448: "Thailand",                                     // TH
	0x544A: "Tajikistan",                                   // TJ
	0x544B: "Tokelau",                                      // TK
	0x544C: "Timor-Leste",                                  // TL
	0x544D: "Turkmenistan",                                 // TM
	0x544E: "Tunisia",                                      // TN
	0x544F: "Tonga",                                        // TO
	0x5452: "T\u00fcrkiye",                                 // TR
	0x5454: "Trinidad and Tobago",                          // TT
	0x5456: "Tuvalu",                                       // TV
	0x5457: "Taiwan",                                       // TW
	0x545A: "Tanzania",                                     // TZ
	0x5541: "Ukraine",                                      // UA
	0x5547: "Uganda",                                       // UG
	0x554D: "United States Minor Outlying Islands",         // UM
	0x5553: "United States",                                // US
	0x5559: "Uruguay",                                      // UY
	0x555A: "Uzbekistan",                                   // UZ
	0x5641: "Vatican City",                                 // VA
	0x5643: "Saint Vincent and the Grenadines",             // VC
	0x5645: "Venezuela",                                    // VE
	0x5647: "Virgin Islands, British",                      // VG
	0x5649: "Virgin Islands, U.S.",                         // VI
	0x564E: "Vietnam",                                      // VN
	0x5655: "Vanuatu",                                      // VU
	0x5746: "Wallis and Futuna",                            // WF
	0x5753: "Samoa",                                        // WS
	0x5945: "Yemen",                                        // YE
	0x5954: "Mayotte",                                      // YT
	0x5A41: "South Africa",                                 // ZA
	0x5A4D: "Zambia",                                       // ZM
	0x5A57: "Zimbabwe",                                     // ZW
	0x4555: "European Union",                               // EU
	0x584B: "Kosovo",                                       // XK
	0x5A5A: "Unknown",                                      // ZZ
}
