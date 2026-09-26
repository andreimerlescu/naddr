package ess

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// IPv8Draft names the specification revision ess implements. IPv8 is
	// an individual Internet-Draft, not an IETF standard; if a later
	// revision changes the address format, this package tracks it.
	IPv8Draft = "draft-thain-ipv8-02"

	// IPv8DraftURL is the datatracker page for IPv8Draft.
	IPv8DraftURL = "https://datatracker.ietf.org/doc/draft-thain-ipv8/"
)

var (
	// ErrInvalidAddr8 is returned for malformed IPv8 addresses.
	ErrInvalidAddr8 = errors.New("invalid IPv8 address")

	// ErrInvalidPrefix8 is returned for malformed IPv8 prefixes.
	ErrInvalidPrefix8 = errors.New("invalid IPv8 prefix")
)

// Addr8 is a 64-bit IPv8 address: a 32-bit ASN routing prefix (r.r.r.r)
// followed by a 32-bit host address (n.n.n.n) with IPv4 semantics. The zero
// value is invalid. Addr8 is comparable.
type Addr8 struct {
	v     uint64
	valid bool
}

// Addr8From builds an IPv8 address from an ASN and an IPv4 host.
func Addr8From(asn uint32, host netip.Addr) (Addr8, error) {
	if !host.IsValid() {
		return Addr8{}, ErrInvalidAddr8
	}
	host = host.Unmap()
	if !host.Is4() {
		return Addr8{}, errors.New("IPv8 host address must be IPv4")
	}
	return addr8FromParts(asn, ipv4Uint32(host)), nil
}

func addr8FromParts(asn, host uint32) Addr8 {
	return Addr8{v: uint64(asn)<<32 | uint64(host), valid: true}
}

// ParseAddr8 parses the 8-octet form (r.r.r.r.n.n.n.n) or ASN dot notation
// (asn.n.n.n.n). Octets and ASNs are decimal without leading zeros.
func ParseAddr8(s string) (Addr8, error) {
	a, _, err := parseAddr8(strings.TrimSpace(s))
	return a, err
}

// parseAddr8 also reports whether s used ASN dot notation.
func parseAddr8(s string) (Addr8, bool, error) {
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 8:
		var v uint64
		for _, p := range parts {
			o, ok := parseOctet(p)
			if !ok {
				return Addr8{}, false, ErrInvalidAddr8
			}
			v = v<<8 | uint64(o)
		}
		return Addr8{v: v, valid: true}, false, nil

	case 5:
		asn, ok := parseCanonicalUint32(parts[0])
		if !ok {
			return Addr8{}, false, ErrInvalidAddr8
		}
		var host uint32
		for _, p := range parts[1:] {
			o, ok := parseOctet(p)
			if !ok {
				return Addr8{}, false, ErrInvalidAddr8
			}
			host = host<<8 | uint32(o)
		}
		return addr8FromParts(asn, host), true, nil

	default:
		return Addr8{}, false, ErrInvalidAddr8
	}
}

func parseOctet(s string) (uint8, bool) {
	if len(s) == 0 || len(s) > 3 {
		return 0, false
	}
	n, ok := parseCanonicalUint32(s)
	if !ok || n > 255 {
		return 0, false
	}
	return uint8(n), true
}

// parseCanonicalUint32 accepts plain decimal with no sign and no leading
// zeros, matching netip's refusal of ambiguous IPv4 octets.
func parseCanonicalUint32(s string) (uint32, bool) {
	if len(s) == 0 || len(s) > 10 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	if n > uint64(^uint32(0)) {
		return 0, false
	}
	return uint32(n), true
}

// IsValid reports whether a holds an address.
func (a Addr8) IsValid() bool { return a.valid }

// IsZero reports whether a is the invalid zero value. It supports the
// encoding/json omitzero option.
func (a Addr8) IsZero() bool { return !a.valid }

// ASN returns the routing prefix as an ASN number.
func (a Addr8) ASN() uint32 { return uint32(a.v >> 32) }

// Host returns the host part as an IPv4 address.
func (a Addr8) Host() netip.Addr {
	if !a.valid {
		return netip.Addr{}
	}
	return ipv4Addr(a.hostUint32())
}

func (a Addr8) hostUint32() uint32 { return uint32(a.v) }

// IsIPv4Compatible reports whether the routing prefix is 0.0.0.0, which
// the draft defines as a plain IPv4 address.
func (a Addr8) IsIPv4Compatible() bool { return a.valid && a.ASN() == 0 }

// String returns the 8-octet form, e.g. 0.0.251.240.192.0.2.1.
func (a Addr8) String() string {
	if !a.valid {
		return "invalid IPv8"
	}
	return ipv4Addr(a.ASN()).String() + "." + a.Host().String()
}

// ASNString returns ASN dot notation, e.g. 64496.192.0.2.1.
func (a Addr8) ASNString() string {
	if !a.valid {
		return "invalid IPv8"
	}
	return strconv.FormatUint(uint64(a.ASN()), 10) + "." + a.Host().String()
}

// MarshalText implements encoding.TextMarshaler using the 8-octet form.
// The zero value marshals as an empty string.
func (a Addr8) MarshalText() ([]byte, error) {
	if !a.valid {
		return []byte{}, nil
	}
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. It accepts either
// form; an empty input yields the zero value.
func (a *Addr8) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*a = Addr8{}
		return nil
	}
	p, err := ParseAddr8(string(b))
	if err != nil {
		return err
	}
	*a = p
	return nil
}

// Prefix8 is an IPv8 network: an Addr8 and a 64-bit prefix length. The
// zero value is invalid.
type Prefix8 struct {
	addr Addr8
	bits uint8
}

// Prefix8From returns the prefix of the given length containing a, with
// host bits masked off.
func Prefix8From(a Addr8, bits int) (Prefix8, error) {
	if !a.valid || bits < 0 || bits > 64 {
		return Prefix8{}, ErrInvalidPrefix8
	}
	return Prefix8{addr: Addr8{v: a.v & mask64(bits), valid: true}, bits: uint8(bits)}, nil
}

// ParsePrefix8 parses r.r.r.r.n.n.n.n/bits (bits 0-64, over the full
// address) or asn.n.n.n.n/bits (bits 0-32, over the host part only).
func ParsePrefix8(s string) (Prefix8, error) {
	addrPart, bitsPart, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return Prefix8{}, ErrInvalidPrefix8
	}

	a, asnForm, err := parseAddr8(addrPart)
	if err != nil {
		return Prefix8{}, ErrInvalidPrefix8
	}

	limit := 64
	if asnForm {
		limit = 32
	}
	bits, err := parsePrefixBits(bitsPart, limit)
	if err != nil {
		return Prefix8{}, err
	}
	if asnForm {
		bits += 32
	}

	return Prefix8From(a, bits)
}

func mask64(bits int) uint64 {
	if bits == 0 {
		return 0
	}
	return ^uint64(0) << uint(64-bits)
}

// IsValid reports whether p holds a prefix.
func (p Prefix8) IsValid() bool { return p.addr.valid }

// Addr returns the masked network address.
func (p Prefix8) Addr() Addr8 { return p.addr }

// Bits returns the 64-bit prefix length.
func (p Prefix8) Bits() int { return int(p.bits) }

// Contains reports whether a is inside p.
func (p Prefix8) Contains(a Addr8) bool {
	return p.addr.valid && a.valid && a.v&mask64(int(p.bits)) == p.addr.v
}

// String returns the 8-octet form with a 64-bit prefix length.
func (p Prefix8) String() string {
	if !p.addr.valid {
		return "invalid IPv8 prefix"
	}
	return p.addr.String() + "/" + strconv.Itoa(int(p.bits))
}

// ASNString returns ASN dot notation with a host-bit prefix length. It
// returns "" when the prefix is shorter than 32 bits, because such a
// prefix spans multiple ASNs and has no ASN dot form.
func (p Prefix8) ASNString() string {
	if !p.addr.valid || p.bits < 32 {
		return ""
	}
	return p.addr.ASNString() + "/" + strconv.Itoa(int(p.bits)-32)
}
