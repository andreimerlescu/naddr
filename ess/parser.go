package ess

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"time"
)

const (
	prefix16Buckets = 1 << 16
	maxTSVLineBytes = 64 << 10
	tsvColumns      = 5
)

type database struct {
	v4 []v4Range
	v6 []v6Range

	// Prefix directories hold the first range whose start address is at or
	// beyond each /16 boundary. lookupV4/lookupV6 also inspect the
	// immediately preceding range because a range may cross a /16 boundary.
	v4Index [prefix16Buckets + 1]uint32
	v6Index [prefix16Buckets + 1]uint32

	// Ranges point to metadata instead of storing ASN data redundantly.
	meta         []asnMeta
	descriptions []string

	// asns is sorted by ASN number and answers ASN-level IPv8 lookups.
	asns []asnEntry

	source   string
	loadedAt time.Time
	info     os.FileInfo
}

type databaseBuilder struct {
	db *database

	descIDs map[string]uint32
	metaIDs map[asnMetaKey]uint32
}

type asnMeta struct {
	number uint32
	descID uint32
}

type asnMetaKey struct {
	number uint32
	descID uint32
}

// loadDatabaseReader parses an IPtoASN TSV stream, transparently
// decompressing gzip input.
func loadDatabaseReader(r io.Reader) (*database, error) {
	br := bufio.NewReaderSize(r, maxTSVLineBytes)

	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("open gzip stream: %w", err)
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, maxTSVLineBytes)
	}

	builder := newDatabaseBuilder()
	lineNo := 0

	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("line %d: TSV line exceeds %d bytes", lineNo+1, maxTSVLineBytes)
		}

		if len(line) > 0 {
			lineNo++
			if parseErr := builder.parseLine(line, lineNo); parseErr != nil {
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

	if len(builder.db.v4) == 0 && len(builder.db.v6) == 0 {
		return nil, errors.New("TSV contained no address ranges")
	}

	return builder.finish(), nil
}

// newDatabaseBuilder deliberately does not preallocate for the full
// IPtoASN dataset: library callers loading small or filtered data should
// not pay for ~18 MB of capacity they never use.
func newDatabaseBuilder() *databaseBuilder {
	return &databaseBuilder{
		db:      &database{},
		descIDs: make(map[string]uint32),
		metaIDs: make(map[asnMetaKey]uint32),
	}
}

func (b *databaseBuilder) finish() *database {
	buildV4Prefix16Index(b.db)
	buildV6Prefix16Index(b.db)
	b.buildASNIndex()
	b.db.loadedAt = time.Now()

	// The dedup maps are startup-only. Dropping references allows GC to
	// reclaim them while the immutable compact slices remain live.
	b.descIDs = nil
	b.metaIDs = nil
	return b.db
}

// buildASNIndex records, per ASN, its most common metadata record and its
// country when every range the ASN holds agrees on one.
func (b *databaseBuilder) buildASNIndex() {
	db := b.db

	type countryAcc struct {
		country uint16
		mixed   bool
	}

	counts := make([]uint32, len(db.meta))
	countries := make(map[uint32]countryAcc)

	note := func(metaID uint32, country uint16) {
		counts[metaID]++
		asn := db.meta[metaID].number
		acc, seen := countries[asn]
		switch {
		case !seen:
			acc = countryAcc{country: country}
		case acc.country != country:
			acc.mixed = true
		}
		countries[asn] = acc
	}
	for _, r := range db.v4 {
		note(r.metaID, r.country)
	}
	for _, r := range db.v6 {
		note(r.metaID, r.country)
	}

	best := make(map[uint32]uint32, len(countries))
	for id, m := range db.meta {
		cur, ok := best[m.number]
		if !ok || counts[id] > counts[cur] {
			best[m.number] = uint32(id)
		}
	}

	db.asns = make([]asnEntry, 0, len(best))
	for asn, metaID := range best {
		country := countryNone
		if acc := countries[asn]; !acc.mixed {
			country = acc.country
		}
		db.asns = append(db.asns, asnEntry{number: asn, metaID: metaID, country: country})
	}
	slices.SortFunc(db.asns, func(a, b asnEntry) int { return cmp.Compare(a.number, b.number) })
}

func (b *databaseBuilder) parseLine(line []byte, lineNo int) error {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})

	if len(line) == 0 || line[0] == '#' {
		return nil
	}

	cols, ok := splitColumns(line)
	if !ok {
		return fmt.Errorf("line %d: expected at least %d tab-separated columns, got %d",
			lineNo, tsvColumns, bytes.Count(line, []byte{'\t'})+1)
	}
	startField, endField, asnField, countryField, descriptionField := cols[0], cols[1], cols[2], cols[3], cols[4]

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

	descID := b.internDescription(descriptionField)
	metaID := b.internMeta(asn, descID)

	if start.Is4() {
		s := ipv4Uint32(start)
		e := ipv4Uint32(end)
		if s > e {
			return fmt.Errorf("line %d: reversed IPv4 range", lineNo)
		}
		if n := len(b.db.v4); n > 0 && s <= b.db.v4[n-1].end {
			return fmt.Errorf("line %d: IPv4 ranges are unsorted or overlapping", lineNo)
		}

		b.db.v4 = append(b.db.v4, v4Range{
			start:   s,
			end:     e,
			metaID:  metaID,
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
	if n := len(b.db.v6); n > 0 && compare128(s, b.db.v6[n-1].end) <= 0 {
		return fmt.Errorf("line %d: IPv6 ranges are unsorted or overlapping", lineNo)
	}

	b.db.v6 = append(b.db.v6, v6Range{
		start:   s,
		end:     e,
		metaID:  metaID,
		country: country,
		prefix:  exactV6Prefix(s, e),
	})
	return nil
}

// splitColumns splits the first four tab-separated columns and returns the
// remainder as the description, which may itself contain tabs.
func splitColumns(line []byte) ([tsvColumns][]byte, bool) {
	var cols [tsvColumns][]byte
	rest := line
	for i := 0; i < tsvColumns-1; i++ {
		head, tail, ok := cutTab(rest)
		if !ok {
			return cols, false
		}
		cols[i] = bytes.TrimSpace(head)
		rest = tail
	}
	cols[tsvColumns-1] = bytes.TrimSpace(rest)
	return cols, true
}

func (b *databaseBuilder) internDescription(raw []byte) uint32 {
	// The temporary []byte->string conversion used only for map probing
	// does not allocate in current Go compilers. A durable string is
	// allocated only on a miss, so each description is stored once.
	if id, ok := b.descIDs[string(raw)]; ok {
		return id
	}

	value := string(raw)
	id := uint32(len(b.db.descriptions))
	b.db.descriptions = append(b.db.descriptions, value)
	b.descIDs[value] = id
	return id
}

func (b *databaseBuilder) internMeta(asn, descID uint32) uint32 {
	key := asnMetaKey{number: asn, descID: descID}
	if id, ok := b.metaIDs[key]; ok {
		return id
	}

	id := uint32(len(b.db.meta))
	b.db.meta = append(b.db.meta, asnMeta{number: asn, descID: descID})
	b.metaIDs[key] = id
	return id
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

func (db *database) metadata(metaID uint32) asnMeta {
	return db.meta[metaID]
}

func (db *database) description(meta asnMeta) string {
	return db.descriptions[meta.descID]
}
