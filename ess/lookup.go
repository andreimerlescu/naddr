package ess

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
)

// asnEntry summarizes one ASN for ASN-level IPv8 answers.
type asnEntry struct {
	number  uint32
	metaID  uint32
	country uint16
}

func (db *database) lookupASN(asn uint32) (asnEntry, bool) {
	i, ok := slices.BinarySearchFunc(db.asns, asn, func(e asnEntry, target uint32) int {
		return cmp.Compare(e.number, target)
	})
	if !ok {
		return asnEntry{}, false
	}
	return db.asns[i], true
}

func (db *database) resultV4(addr netip.Addr) (Result, bool) {
	host := ipv4Uint32(addr)
	row, ok := db.lookupV4(host)
	if !ok {
		return Result{}, false
	}

	meta := db.metadata(row.metaID)
	a8 := addr8FromParts(meta.number, host)

	return Result{
		Version:     4,
		Country:     countryName(row.country),
		CountryCode: countryCode(row.country),
		Number:      meta.number,
		ASN:         formatASN(meta.number),
		Description: db.description(meta),
		Routed:      meta.number != 0,
		Address:     addr,
		Range:       formatV4Range(row),
		Address8:    a8,
		IP8:         a8.String(),
		IP8ASN:      a8.ASNString(),
		Range8:      formatV8Range(meta.number, row),
		Range8ASN:   formatV8ASNRange(meta.number, row),
	}, true
}

func (db *database) resultV6(addr netip.Addr) (Result, bool) {
	row, ok := db.lookupV6(uint128FromAddr(addr))
	if !ok {
		return Result{}, false
	}

	meta := db.metadata(row.metaID)

	return Result{
		Version:     6,
		Country:     countryName(row.country),
		CountryCode: countryCode(row.country),
		Number:      meta.number,
		ASN:         formatASN(meta.number),
		Description: db.description(meta),
		Routed:      meta.number != 0,
		Address:     addr,
		Range:       formatV6Range(row),
	}, true
}

// resultV8 answers a non-zero-prefix IPv8 address. See LookupAddr8.
func (db *database) resultV8(a Addr8) (Result, bool) {
	asn := a.ASN()

	if row, ok := db.lookupV4(a.hostUint32()); ok {
		if meta := db.metadata(row.metaID); meta.number == asn {
			return db.result8(a, meta, row.country, row), true
		}
	}

	entry, ok := db.lookupASN(asn)
	if !ok {
		return Result{}, false
	}

	wholeASN := v4Range{start: 0, end: ^uint32(0), prefix: 0}
	return db.result8(a, db.metadata(entry.metaID), entry.country, wholeASN), true
}

func (db *database) result8(a Addr8, meta asnMeta, country uint16, block v4Range) Result {
	return Result{
		Version:     8,
		Country:     countryName(country),
		CountryCode: countryCode(country),
		Number:      meta.number,
		ASN:         formatASN(meta.number),
		Description: db.description(meta),
		Routed:      meta.number != 0,
		Address8:    a,
		IP8:         a.String(),
		IP8ASN:      a.ASNString(),
		Range8:      formatV8Range(meta.number, block),
		Range8ASN:   formatV8ASNRange(meta.number, block),
	}
}

// formatV8Range renders an IPv4 range under an ASN prefix in 8-octet form.
// Exact CIDRs use 64-bit prefix lengths (IPv4 /24 under an ASN is /56).
func formatV8Range(asn uint32, r v4Range) string {
	start := addr8FromParts(asn, r.start)
	if r.prefix != 255 {
		return start.String() + "/" + strconv.Itoa(32+int(r.prefix))
	}
	return start.String() + "-" + addr8FromParts(asn, r.end).String()
}

// formatV8ASNRange renders the same range in ASN dot notation, where the
// prefix length counts host bits only.
func formatV8ASNRange(asn uint32, r v4Range) string {
	start := addr8FromParts(asn, r.start)
	if r.prefix != 255 {
		return start.ASNString() + "/" + strconv.Itoa(int(r.prefix))
	}
	return start.ASNString() + "-" + addr8FromParts(asn, r.end).ASNString()
}
