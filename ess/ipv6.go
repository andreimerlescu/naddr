package ess

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"strconv"
)

type uint128 struct {
	hi uint64
	lo uint64
}

type v6Range struct {
	start   uint128
	end     uint128
	metaID  uint32
	country uint16
	prefix  uint8
	_       uint8
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

func buildV6Prefix16Index(db *database) {
	cursor := 0
	for bucket := 0; bucket < prefix16Buckets; bucket++ {
		for cursor < len(db.v6) && int(db.v6[cursor].start.hi>>48) < bucket {
			cursor++
		}
		db.v6Index[bucket] = uint32(cursor)
	}
	db.v6Index[prefix16Buckets] = uint32(len(db.v6))
}

func (db *database) lookupV6(addr uint128) (v6Range, bool) {
	bucket := int(addr.hi >> 48)
	lo := int(db.v6Index[bucket])
	hi := int(db.v6Index[bucket+1])
	if lo > 0 {
		lo--
	}

	base := lo
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if compare128(db.v6[mid].start, addr) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == base {
		return v6Range{}, false
	}
	r := db.v6[lo-1]
	return r, compare128(addr, r.end) <= 0
}

func formatV6Range(r v6Range) string {
	if r.prefix != 255 {
		return r.start.addr().String() + "/" + strconv.Itoa(int(r.prefix))
	}
	return r.start.addr().String() + "-" + r.end.addr().String()
}
