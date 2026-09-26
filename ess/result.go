package ess

import (
	"net/netip"
	"strconv"
	"time"
)

// Result is the stable public representation of a lookup.
//
// Version is 4, 6, or 8.
//
//   - Version 4 results also carry the address and range re-expressed under
//     the owning ASN's IPv8 routing prefix (IP8, IP8ASN, Range8, Range8ASN).
//   - Version 6 results never carry IPv8 fields; the draft extends IPv4 only.
//   - Version 8 results carry only IPv8 fields. Address and Range are empty
//     because the host part of an IPv8 address belongs to its ASN and is not
//     a public IPv4 address.
type Result struct {
	Version     int    `json:"version"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Number      uint32 `json:"number"`
	ASN         string `json:"asn"`
	Description string `json:"description"`

	// Routed is false for IPtoASN "Not routed" entries (ASN 0).
	Routed bool `json:"routed"`

	Address netip.Addr `json:"address,omitzero"`
	Range   string     `json:"range,omitempty"`

	Address8  Addr8  `json:"-"`
	IP8       string `json:"ip8,omitempty"`
	IP8ASN    string `json:"ip8asn,omitempty"`
	Range8    string `json:"range8,omitempty"`
	Range8ASN string `json:"range8asn,omitempty"`
}

// Stats describes the database currently serving lookups.
type Stats struct {
	IPv4Ranges   int `json:"ipv4_ranges"`
	IPv6Ranges   int `json:"ipv6_ranges"`
	ASNs         int `json:"asns"`
	ASNMetadata  int `json:"asn_metadata"`
	Descriptions int `json:"descriptions"`

	// Source is the file path, or "reader" for Load.
	Source   string    `json:"source,omitempty"`
	LoadedAt time.Time `json:"loaded_at,omitzero"`

	// Reloads counts successful reloads since Open.
	Reloads           uint64    `json:"reloads"`
	LastReloadAttempt time.Time `json:"last_reload_attempt,omitzero"`

	// LastReloadError is empty when the most recent reload succeeded.
	LastReloadError string `json:"last_reload_error,omitempty"`
}

func formatASN(n uint32) string {
	return "AS" + strconv.FormatUint(uint64(n), 10)
}
