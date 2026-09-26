package ess

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
)

var (
	// ErrAddressNotFound is returned by LookupString when an address parses
	// correctly but is absent from the loaded IPtoASN database.
	ErrAddressNotFound = errors.New("address not found")

	// ErrNilResolver is returned when a lookup is attempted on a nil or
	// uninitialized Resolver.
	ErrNilResolver = errors.New("nil resolver")
)

// Resolver owns an immutable, in-memory IPtoASN database. A Resolver is safe
// for concurrent lookups after Open or Load returns successfully.
type Resolver struct {
	db *database
}

// Open loads an external IPtoASN TSV file from path.
func Open(path string) (*Resolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	resolver, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	return resolver, nil
}

// Load loads IPtoASN TSV data from r. It is useful to callers that already
// manage the data source themselves without requiring filesystem access.
func Load(r io.Reader) (*Resolver, error) {
	if r == nil {
		return nil, errors.New("nil database reader")
	}
	db, err := loadDatabaseReader(r)
	if err != nil {
		return nil, err
	}
	return &Resolver{db: db}, nil
}

// Lookup resolves addr. IPv4-mapped IPv6 addresses are normalized to IPv4.
func (r *Resolver) Lookup(addr netip.Addr) (Result, bool) {
	if r == nil || r.db == nil || !addr.IsValid() || addr.Zone() != "" {
		return Result{}, false
	}

	addr = addr.Unmap()
	if addr.Is4() {
		row, ok := r.db.lookupV4(ipv4Uint32(addr))
		if !ok {
			return Result{}, false
		}
		meta := r.db.metadata(row.metaID)
		return Result{
			Version:     4,
			Country:     countryName(row.country),
			CountryCode: countryCode(row.country),
			Number:      meta.number,
			ASN:         "AS" + strconv.FormatUint(uint64(meta.number), 10),
			Description: r.db.description(meta),
			Address:     addr,
			Range:       formatV4Range(row),
		}, true
	}

	row, ok := r.db.lookupV6(uint128FromAddr(addr))
	if !ok {
		return Result{}, false
	}
	meta := r.db.metadata(row.metaID)
	return Result{
		Version:     6,
		Country:     countryName(row.country),
		CountryCode: countryCode(row.country),
		Number:      meta.number,
		ASN:         "AS" + strconv.FormatUint(uint64(meta.number), 10),
		Description: r.db.description(meta),
		Address:     addr,
		Range:       formatV6Range(row),
	}, true
}

// LookupString parses and resolves an IP address string.
func (r *Resolver) LookupString(s string) (Result, error) {
	if r == nil || r.db == nil {
		return Result{}, ErrNilResolver
	}
	addr, err := ParseAddr(s)
	if err != nil {
		return Result{}, err
	}
	result, ok := r.Lookup(addr)
	if !ok {
		return Result{}, ErrAddressNotFound
	}
	return result, nil
}

// Stats returns database cardinalities useful for diagnostics and startup logs.
func (r *Resolver) Stats() Stats {
	if r == nil || r.db == nil {
		return Stats{}
	}
	return Stats{
		IPv4Ranges:   len(r.db.v4),
		IPv6Ranges:   len(r.db.v6),
		ASNMetadata:  len(r.db.meta),
		Descriptions: len(r.db.descriptions),
	}
}
