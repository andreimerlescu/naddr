package ess

import "net/netip"

// Result is the stable public representation of an IPtoASN lookup.
// Internal compact range/index structures intentionally remain private so
// callers are not coupled to the database storage implementation.
type Result struct {
	Version     int
	Country     string
	CountryCode string
	Number      uint32
	ASN         string
	Description string
	Address     netip.Addr
	Range       string
}

// Stats describes the immutable in-memory database after loading.
type Stats struct {
	IPv4Ranges   int
	IPv6Ranges   int
	ASNMetadata  int
	Descriptions int
}
