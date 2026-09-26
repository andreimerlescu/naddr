package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/andreimerlescu/naddr/ess"
)

type ipResponse struct {
	Error       *string `json:"error"`
	Success     bool    `json:"success"`
	V           int     `json:"v"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	N           uint32  `json:"n"`
	ASN         string  `json:"asn"`
	Description string  `json:"description"`
	IP4         string  `json:"ip4"`
	IP6         string  `json:"ip6"`
	IP8         string  `json:"ip8"`
	Range4      string  `json:"range4"`
	Range6      string  `json:"range6"`
	Range8      string  `json:"range8"`
}

type boolResponse struct {
	Error   *string `json:"error"`
	Success bool    `json:"success"`
}

// NewHandler returns the HTTP API backed by resolver.
func NewHandler(resolver *ess.Resolver) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/ip", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addrText := strings.TrimSpace(r.URL.Query().Get("addr"))
		if addrText == "" {
			writeIPError(w, http.StatusBadRequest, "missing addr")
			return
		}

		addr, err := ess.ParseAddr(addrText)
		if err != nil {
			writeIPError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeLookup(w, resolver, addr, "public, max-age=3600")
	}))

	mux.HandleFunc("/my", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addr, err := requesterAddr(r)
		if err != nil {
			writeIPError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeLookup(w, resolver, addr, "no-store")
	}))

	mux.HandleFunc("/is/addr", getOnly(func(w http.ResponseWriter, r *http.Request) {
		addrText := strings.TrimSpace(r.URL.Query().Get("ess"))
		if addrText == "" {
			writeBoolError(w, http.StatusBadRequest, "missing ess")
			return
		}

		addr, err := ess.ParseAddr(addrText)
		if err != nil {
			writeBoolError(w, http.StatusBadRequest, err.Error())
			return
		}

		prefix, err := ess.ParseMembershipPrefix(
			addr,
			strings.TrimSpace(r.URL.Query().Get("in")),
		)
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
		writeJSON(
			w,
			http.StatusOK,
			"no-store",
			boolResponse{Success: true},
		)
	}))

	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if !resolverReady(resolver) {
			writeBoolError(
				w,
				http.StatusServiceUnavailable,
				"database not loaded",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			"no-store",
			boolResponse{Success: true},
		)
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeBoolError(w, http.StatusNotFound, "route not found")
	})

	return mux
}

func resolverReady(resolver *ess.Resolver) bool {
	if resolver == nil {
		return false
	}

	stats := resolver.Stats()

	return stats.IPv4Ranges+stats.IPv6Ranges > 0
}

func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet &&
			r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeBoolError(
				w,
				http.StatusMethodNotAllowed,
				"method not allowed",
			)
			return
		}

		next(w, r)
	}
}

func requesterAddr(r *http.Request) (netip.Addr, error) {
	remoteText := r.RemoteAddr

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteText = host
	}

	remoteText = strings.Trim(remoteText, "[]")

	remote, err := ess.ParseAddr(remoteText)
	if err != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}

	// Preserve the original trust model: proxy headers are only honored for a
	// loopback-connected peer.
	if !remote.IsLoopback() {
		return remote, nil
	}

	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if addr, err := ess.ParseAddr(realIP); err == nil {
			return addr, nil
		}
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first, _, _ := strings.Cut(forwarded, ","); strings.TrimSpace(first) != "" {
			if addr, err := ess.ParseAddr(strings.TrimSpace(first)); err == nil {
				return addr, nil
			}
		}
	}

	return remote, nil
}

func writeLookup(
	w http.ResponseWriter,
	resolver *ess.Resolver,
	addr netip.Addr,
	cacheControl string,
) {
	if !resolverReady(resolver) {
		writeIPError(
			w,
			http.StatusServiceUnavailable,
			"database not loaded",
		)
		return
	}

	result, ok := resolver.Lookup(addr)
	if !ok {
		writeIPError(
			w,
			http.StatusNotFound,
			ess.ErrAddressNotFound.Error(),
		)
		return
	}

	response := ipResponse{
		Error:       nil,
		Success:     true,
		V:           result.Version,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		N:           result.Number,
		ASN:         result.ASN,
		Description: result.Description,
	}

	if result.Version == 4 {
		response.IP4 = result.Address.String()
		response.Range4 = result.Range
	} else {
		response.IP6 = result.Address.String()
		response.Range6 = result.Range
	}

	writeJSON(w, http.StatusOK, cacheControl, response)
}

func writeIPError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(w, status, "no-store", ipResponse{
		Error:   stringPtr(message),
		Success: false,
	})
}

func writeBoolError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(w, status, "no-store", boolResponse{
		Error:   stringPtr(message),
		Success: false,
	})
}

func stringPtr(s string) *string {
	return &s
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	cacheControl string,
	value any,
) {
	h := w.Header()

	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", cacheControl)
	h.Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}
