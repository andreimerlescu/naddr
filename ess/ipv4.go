package ess

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"strconv"
)

type v4Range struct {
	start   uint32
	end     uint32
	metaID  uint32
	country uint16
	prefix  uint8
	_       uint8
}

func ipv4Uint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func ipv4Addr(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

func exactV4Prefix(start, end uint32) uint8 {
	prefix := bits.LeadingZeros32(start ^ end)
	mask := ^uint32(0) << uint(32-prefix)
	if start&^mask != 0 || end != start|^mask {
		return 255
	}
	return uint8(prefix)
}

func buildV4Prefix16Index(db *database) {
	cursor := 0
	for bucket := 0; bucket < prefix16Buckets; bucket++ {
		for cursor < len(db.v4) && int(db.v4[cursor].start>>16) < bucket {
			cursor++
		}
		db.v4Index[bucket] = uint32(cursor)
	}
	db.v4Index[prefix16Buckets] = uint32(len(db.v4))
}

func (db *database) lookupV4(addr uint32) (v4Range, bool) {
	bucket := int(addr >> 16)
	lo := int(db.v4Index[bucket])
	hi := int(db.v4Index[bucket+1])
	if lo > 0 {
		lo--
	}

	base := lo
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if db.v4[mid].start <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == base {
		return v4Range{}, false
	}
	r := db.v4[lo-1]
	return r, addr <= r.end
}

func formatV4Range(r v4Range) string {
	start := ipv4Addr(r.start)
	if r.prefix != 255 {
		return start.String() + "/" + strconv.Itoa(int(r.prefix))
	}
	return start.String() + "-" + ipv4Addr(r.end).String()
}
