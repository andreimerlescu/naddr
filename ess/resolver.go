package ess

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrAddressNotFound is returned when an address parses correctly but
	// is absent from the loaded database.
	ErrAddressNotFound = errors.New("address not found")

	// ErrNilResolver is returned when a nil or unloaded Resolver is used.
	ErrNilResolver = errors.New("nil resolver")

	// ErrNoSource is returned by Reload and Watch for a Resolver built with
	// Load, which has no file to re-read.
	ErrNoSource = errors.New("resolver has no file source")
)

// Resolver resolves addresses against an in-memory IPtoASN database.
//
// A Resolver is safe for concurrent use. Lookups read an immutable database
// through an atomic pointer; Reload and Watch replace that pointer only
// after a complete replacement has loaded and validated. A Resolver must
// not be copied after first use.
type Resolver struct {
	db           atomic.Pointer[database]
	path         string
	pollInterval time.Duration

	reloadMu sync.Mutex
	status   atomic.Pointer[reloadStatus]
	reloads  atomic.Uint64
}

type reloadStatus struct {
	attempt time.Time
	err     error
}

// Open loads the IPtoASN TSV file at path, plain or gzip-compressed. The
// Resolver remembers path for Reload and Watch.
func Open(path string) (*Resolver, error) {
	db, err := loadDatabaseFile(path)
	if err != nil {
		return nil, err
	}

	r := &Resolver{path: path, pollInterval: DefaultPollInterval}
	r.db.Store(db)
	return r, nil
}

// Load reads IPtoASN TSV data, plain or gzip-compressed, from src. The
// returned Resolver cannot Reload or Watch; build a new one instead.
func Load(src io.Reader) (*Resolver, error) {
	if src == nil {
		return nil, errors.New("nil database reader")
	}

	db, err := loadDatabaseReader(src)
	if err != nil {
		return nil, err
	}
	db.source = "reader"

	r := &Resolver{}
	r.db.Store(db)
	return r, nil
}

func loadDatabaseFile(path string) (*database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	db, err := loadDatabaseReader(f)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	db.source = path
	db.info = info

	return db, nil
}

func (r *Resolver) current() *database {
	if r == nil {
		return nil
	}
	return r.db.Load()
}

// Ready reports whether r holds a usable database.
func (r *Resolver) Ready() bool {
	db := r.current()
	return db != nil && len(db.v4)+len(db.v6) > 0
}

// Lookup resolves an IPv4 or IPv6 address. IPv4-mapped IPv6 addresses are
// normalized to IPv4. IPv4 results include the derived IPv8 fields.
func (r *Resolver) Lookup(addr netip.Addr) (Result, bool) {
	db := r.current()
	if db == nil || !addr.IsValid() || addr.Zone() != "" {
		return Result{}, false
	}

	addr = addr.Unmap()
	if addr.Is4() {
		return db.resultV4(addr)
	}
	return db.resultV6(addr)
}

// LookupAddr8 resolves an IPv8 address.
//
// An address with ASN prefix 0 is IPv4 (per the draft) and returns a
// Version 4 Result. Otherwise the Result has Version 8: if the host part
// falls inside an IPv4 range IPtoASN assigns to the same ASN, that range
// supplies the country and range; if not, the Result describes the ASN as a
// whole, with Range8 covering the ASN's entire block.
func (r *Resolver) LookupAddr8(a Addr8) (Result, bool) {
	db := r.current()
	if db == nil || !a.IsValid() {
		return Result{}, false
	}
	if a.IsIPv4Compatible() {
		return db.resultV4(a.Host())
	}
	return db.resultV8(a)
}

// LookupString parses and resolves an IPv4, IPv6, or IPv8 address. IPv8
// accepts both the 8-octet form and ASN dot notation.
func (r *Resolver) LookupString(s string) (Result, error) {
	if r.current() == nil {
		return Result{}, ErrNilResolver
	}

	addr, err := ParseAddr(s)
	if err == nil {
		if res, ok := r.Lookup(addr); ok {
			return res, nil
		}
		return Result{}, ErrAddressNotFound
	}
	if !errors.Is(err, ErrInvalidAddress) {
		return Result{}, err
	}

	a8, err := ParseAddr8(s)
	if err != nil {
		return Result{}, ErrInvalidAddress
	}
	if res, ok := r.LookupAddr8(a8); ok {
		return res, nil
	}
	return Result{}, ErrAddressNotFound
}

// Reload re-reads the file the Resolver was opened from. On success the new
// database replaces the old one atomically. On failure the old database
// keeps serving and the error is recorded in Stats.
func (r *Resolver) Reload() error {
	if r.current() == nil {
		return ErrNilResolver
	}
	if r.path == "" {
		return ErrNoSource
	}

	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	db, err := loadDatabaseFile(r.path)
	r.status.Store(&reloadStatus{attempt: time.Now(), err: err})
	if err != nil {
		return err
	}

	r.db.Store(db)
	r.reloads.Add(1)
	return nil
}

// Stats describes the database currently serving lookups.
func (r *Resolver) Stats() Stats {
	db := r.current()
	if db == nil {
		return Stats{}
	}

	s := Stats{
		IPv4Ranges:   len(db.v4),
		IPv6Ranges:   len(db.v6),
		ASNs:         len(db.asns),
		ASNMetadata:  len(db.meta),
		Descriptions: len(db.descriptions),
		Source:       db.source,
		LoadedAt:     db.loadedAt,
		Reloads:      r.reloads.Load(),
	}
	if st := r.status.Load(); st != nil {
		s.LastReloadAttempt = st.attempt
		if st.err != nil {
			s.LastReloadError = st.err.Error()
		}
	}
	return s
}
