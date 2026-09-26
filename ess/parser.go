package ess

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	v4CapacityHint   = 540_000
	v6CapacityHint   = 185_000
	metaCapacityHint = 100_000
	descCapacityHint = 100_000

	prefix16Buckets = 1 << 16
	maxTSVLineBytes = 64 << 10
)

type database struct {
	v4 []v4Range
	v6 []v6Range

	// Prefix directories hold the first range whose start address is at or
	// beyond each /16 boundary. lookupV4/lookupV6 also inspect the immediately
	// preceding range because a range may cross a /16 boundary.
	v4Index [prefix16Buckets + 1]uint32
	v6Index [prefix16Buckets + 1]uint32

	// Ranges point to metadata instead of storing ASN data redundantly.
	meta         []asnMeta
	descriptions []string
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

func loadDatabaseReader(r io.Reader) (*database, error) {
	builder := newDatabaseBuilder()
	br := bufio.NewReaderSize(r, maxTSVLineBytes)
	lineNo := 0

	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("TSV line exceeds %d bytes", maxTSVLineBytes)
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

func newDatabaseBuilder() *databaseBuilder {
	return &databaseBuilder{
		db: &database{
			v4:           make([]v4Range, 0, v4CapacityHint),
			v6:           make([]v6Range, 0, v6CapacityHint),
			meta:         make([]asnMeta, 0, metaCapacityHint),
			descriptions: make([]string, 0, descCapacityHint),
		},
		descIDs: make(map[string]uint32, descCapacityHint),
		metaIDs: make(map[asnMetaKey]uint32, metaCapacityHint),
	}
}

func (b *databaseBuilder) finish() *database {
	buildV4Prefix16Index(b.db)
	buildV6Prefix16Index(b.db)

	// The dedup maps are startup-only. Dropping references allows GC to reclaim
	// them while the immutable compact slices remain live for serving requests.
	b.descIDs = nil
	b.metaIDs = nil
	return b.db
}

func (b *databaseBuilder) parseLine(line []byte, lineNo int) error {
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
	countryField, descriptionField, ok := cutTab(rest)
	if !ok {
		return fmt.Errorf("line %d: missing AS_description column", lineNo)
	}

	startField = bytes.TrimSpace(startField)
	endField = bytes.TrimSpace(endField)
	asnField = bytes.TrimSpace(asnField)
	countryField = bytes.TrimSpace(countryField)
	descriptionField = bytes.TrimSpace(descriptionField)

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

func (b *databaseBuilder) internDescription(raw []byte) uint32 {
	// The temporary []byte->string conversion used only for map probing does
	// not escape in current Go compilers. Allocate a durable string only on a
	// genuine miss so duplicate descriptions are stored exactly once.
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
