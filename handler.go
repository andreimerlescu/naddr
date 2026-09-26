package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/andreimerlescu/naddr/ess"
)

const (
	cacheLookup = "public, max-age=3600"
	cacheNever  = "no-store"
)

// ipResponse is the /ip and /my envelope. Every key is always present so
// clients can rely on a fixed schema; unused fields are empty strings.
type ipResponse struct {
	Error       *string `json:"error"`
	Success     bool    `json:"success"`
	V           int     `json:"v"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	N           uint32  `json:"n"`
	ASN         string  `json:"asn"`
	Description string  `json:"description"`
	Routed      bool    `json:"routed"`
	IP4         string  `json:"ip4"`
	IP6         string  `json:"ip6"`
	IP8         string  `json:"ip8"`
	IP8ASN      string  `json:"ip8asn"`
	Range4      string  `json:"range4"`
	Range6      string  `json:"range6"`
	Range8      string  `json:"range8"`
	Range8ASN   string  `json:"range8asn"`
}

type boolResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
}

type membershipResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
	V       int     `json:"v"`
	Member  bool    `json:"member"`
	Network string  `json:"network"`
}

type readyResponse struct {
	Error           *string `json:"error"`
	Success         bool    `json:"success"`
	LoadedAt        string  `json:"loaded_at"`
	IPv4Ranges      int     `json:"ipv4_ranges"`
	IPv6Ranges      int     `json:"ipv6_ranges"`
	ASNs            int     `json:"asns"`
	Reloads         uint64  `json:"reloads"`
	LastReloadError *string `json:"last_reload_error"`
}

type versionResponse struct {
	Version   string `json:"version"`
	IPv8Draft string `json:"ipv8_draft"`
}

// HandlerOptions configures NewHandler. Values are used as given; see
// parseConfig for the binary's defaults.
type HandlerOptions struct {
	TrustedProxies []netip.Prefix
	AllowedHosts   []string
	AccessLog      bool
	Logger         *slog.Logger
}

// NewHandler returns the naddr HTTP API backed by resolver.
func NewHandler(resolver *ess.Resolver, opts HandlerOptions) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	trusted := opts.TrustedProxies

	mux := http.NewServeMux()

	mux.HandleFunc("/ip", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addrText := strings.TrimSpace(r.URL.Query().Get("addr"))
		if addrText == "" {
			writeIPError(w, http.StatusBadRequest, "missing addr")
			return
		}

		result, err := resolver.LookupString(addrText)
		if err != nil {
			writeLookupError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, cacheLookup, newIPResponse(result))
	}))

	mux.HandleFunc("/my", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addr, err := requesterAddr(r, trusted)
		if err != nil {
			writeIPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if addr.IsLoopback() {
			writeIPError(w, http.StatusBadRequest,
				"requester address is loopback; /my needs a reverse proxy that sets X-Forwarded-For or X-Real-IP")
			return
		}
		if !resolver.Ready() {
			writeIPError(w, http.StatusServiceUnavailable, "database not loaded")
			return
		}

		result, ok := resolver.Lookup(addr)
		if !ok {
			writeIPError(w, http.StatusNotFound, ess.ErrAddressNotFound.Error())
			return
		}

		writeJSON(w, http.StatusOK, cacheNever, newIPResponse(result))
	}))

	mux.HandleFunc("/is/addr", getOnly(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		addrText := strings.TrimSpace(query.Get("ess"))
		if addrText == "" {
			writeBoolError(w, http.StatusBadRequest, "missing ess")
			return
		}

		m, err := ess.Check(addrText, query.Get("in"))
		if err != nil {
			writeBoolError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, cacheNever, membershipResponse{
			Success: true,
			V:       m.Version,
			Member:  m.Member,
			Network: m.Network,
		})
	}))

	mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, cacheNever, boolResponse{Success: true})
	}))

	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if !resolver.Ready() {
			writeBoolError(w, http.StatusServiceUnavailable, "database not loaded")
			return
		}

		s := resolver.Stats()
		resp := readyResponse{
			Success:    true,
			LoadedAt:   s.LoadedAt.UTC().Format(time.RFC3339),
			IPv4Ranges: s.IPv4Ranges,
			IPv6Ranges: s.IPv6Ranges,
			ASNs:       s.ASNs,
			Reloads:    s.Reloads,
		}
		if s.LastReloadError != "" {
			resp.LastReloadError = stringPtr(s.LastReloadError)
		}

		writeJSON(w, http.StatusOK, cacheNever, resp)
	}))

	mux.HandleFunc("/version", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, cacheNever, versionResponse{
			Version:   BinaryVersion(),
			IPv8Draft: ess.IPv8Draft,
		})
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeBoolError(w, http.StatusNotFound, "route not found")
	})

	var h http.Handler = mux
	h = withHostCheck(h, opts.AllowedHosts)
	if opts.AccessLog {
		h = withAccessLog(h, logger)
	}
	return h
}

func newIPResponse(res ess.Result) ipResponse {
	resp := ipResponse{
		Success:     true,
		V:           res.Version,
		Country:     res.Country,
		CountryCode: res.CountryCode,
		N:           res.Number,
		ASN:         res.ASN,
		Description: res.Description,
		Routed:      res.Routed,
		IP8:         res.IP8,
		IP8ASN:      res.IP8ASN,
		Range8:      res.Range8,
		Range8ASN:   res.Range8ASN,
	}

	switch res.Version {
	case 4:
		resp.IP4 = res.Address.String()
		resp.Range4 = res.Range
	case 6:
		resp.IP6 = res.Address.String()
		resp.Range6 = res.Range
	}

	return resp
}

func writeLookupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ess.ErrNilResolver):
		writeIPError(w, http.StatusServiceUnavailable, "database not loaded")
	case errors.Is(err, ess.ErrAddressNotFound):
		writeIPError(w, http.StatusNotFound, err.Error())
	default:
		writeIPError(w, http.StatusBadRequest, err.Error())
	}
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

// requesterAddr returns the client address for /my.
//
// Proxy headers are honored only when the direct peer is a trusted proxy.
// X-Forwarded-For is walked right to left and the first untrusted hop is
// the client: proxies append, so entries to the left of the last trusted
// hop are client-controlled and cannot be believed. X-Real-IP is used only
// when X-Forwarded-For is absent.
func requesterAddr(r *http.Request, trusted []netip.Prefix) (netip.Addr, error) {
	remote, err := ess.ParseAddr(hostOnly(r.RemoteAddr))
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	if !isTrusted(remote, trusted) {
		return remote, nil
	}

	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		var hops []string
		for _, v := range values {
			hops = append(hops, strings.Split(v, ",")...)
		}

		client := remote
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if hop == "" {
				continue
			}
			addr, err := ess.ParseAddr(hostOnly(hop))
			if err != nil {
				// A malformed hop breaks the chain of trust.
				return remote, nil
			}
			client = addr
			if !isTrusted(addr, trusted) {
				return addr, nil
			}
		}
		return client, nil
	}

	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if addr, err := ess.ParseAddr(hostOnly(realIP)); err == nil {
			return addr, nil
		}
	}

	return remote, nil
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}

// withHostCheck rejects requests whose Host header is not allowlisted,
// which defeats DNS-rebinding attacks against a localhost service.
func withHostCheck(next http.Handler, allowed []string) http.Handler {
	if len(allowed) == 0 {
		return next
	}

	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		set[normalizeHost(h)] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := set[normalizeHost(r.Host)]; !ok {
			writeBoolError(w, http.StatusMisdirectedRequest, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// withAccessLog logs method, path, status, and latency. Query strings are
// not logged because they carry the addresses being looked up.
func withAccessLog(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote", r.RemoteAddr),
			slog.String("proto", r.Proto),
		)
	})
}

func writeIPError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, cacheNever, ipResponse{Error: stringPtr(message)})
}

func writeBoolError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, cacheNever, boolResponse{Error: stringPtr(message)})
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
