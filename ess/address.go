package ess

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrInvalidAddress is returned when input is not a valid IP address.
	ErrInvalidAddress = errors.New("invalid IP address")

	// ErrScopedAddress is returned for IPv6 addresses carrying a zone.
	ErrScopedAddress = errors.New("scoped IPv6 addresses are not supported")
)

// ParseAddr parses an IPv4 or IPv6 address, rejects scoped IPv6 addresses,
// and normalizes IPv4-mapped IPv6 addresses to IPv4.
func ParseAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, ErrInvalidAddress
	}
	if addr.Zone() != "" {
		return netip.Addr{}, ErrScopedAddress
	}
	return addr.Unmap(), nil
}

// ParseMembershipPrefix accepts ip/cidr, /cidr, or cidr. The latter two
// build the prefix around addr, which is useful for finding the network
// that contains addr (and always contains it).
func ParseMembershipPrefix(addr netip.Addr, spec string) (netip.Prefix, error) {
	if !addr.IsValid() || addr.Zone() != "" {
		return netip.Prefix{}, ErrInvalidAddress
	}
	addr = addr.Unmap()

	spec = strings.TrimSpace(spec)
	if spec == "" {
		return netip.Prefix{}, errors.New("missing in")
	}

	if bitsText, relative := relativeBits(spec); relative {
		bits, err := parsePrefixBits(bitsText, addr.BitLen())
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}

	parsed, err := netip.ParsePrefix(spec)
	if err != nil {
		return netip.Prefix{}, errors.New("invalid CIDR")
	}
	prefix, ok := normalizePrefix(parsed)
	if !ok {
		return netip.Prefix{}, errors.New("invalid CIDR")
	}
	if prefix.Addr().Is4() != addr.Is4() {
		return netip.Prefix{}, errors.New("IP and CIDR address families differ")
	}
	return prefix, nil
}

// Contains reports whether addr is inside prefix after normalizing
// IPv4-mapped forms. Different address families return false.
func Contains(addr netip.Addr, prefix netip.Prefix) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	p, ok := normalizePrefix(prefix)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() != p.Addr().Is4() {
		return false
	}
	return p.Contains(addr)
}

// In parses addrText and spec and reports IPv4/IPv6 CIDR membership.
func In(addrText, spec string) (bool, error) {
	addr, err := ParseAddr(addrText)
	if err != nil {
		return false, err
	}
	prefix, err := ParseMembershipPrefix(addr, spec)
	if err != nil {
		return false, err
	}
	return prefix.Contains(addr), nil
}

// Membership is the answer to a CIDR membership check.
type Membership struct {
	// Version is 4, 6, or 8: the family of the checked address.
	Version int
	// Member reports whether the address is inside Network.
	Member bool
	// Network is the normalized network the address was tested against.
	Network string
}

// Check parses an IPv4, IPv6, or IPv8 address and a network spec and
// reports membership along with the normalized network. See
// ParseMembershipPrefix and ParseMembershipPrefix8 for accepted specs.
func Check(addrText, spec string) (Membership, error) {
	addr, err := ParseAddr(addrText)
	if err == nil {
		prefix, err := ParseMembershipPrefix(addr, spec)
		if err != nil {
			return Membership{}, err
		}
		version := 6
		if addr.Is4() {
			version = 4
		}
		return Membership{Version: version, Member: prefix.Contains(addr), Network: prefix.String()}, nil
	}
	if !errors.Is(err, ErrInvalidAddress) {
		return Membership{}, err
	}

	a8, err := ParseAddr8(addrText)
	if err != nil {
		return Membership{}, ErrInvalidAddress
	}
	prefix, err := ParseMembershipPrefix8(a8, spec)
	if err != nil {
		return Membership{}, err
	}
	return Membership{Version: 8, Member: prefix.Contains(a8), Network: prefix.String()}, nil
}

// ParseMembershipPrefix8 accepts an IPv8 prefix in either form (see
// ParsePrefix8), or /bits or bits (0-64) relative to a.
func ParseMembershipPrefix8(a Addr8, spec string) (Prefix8, error) {
	if !a.IsValid() {
		return Prefix8{}, ErrInvalidAddr8
	}

	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Prefix8{}, errors.New("missing in")
	}

	if bitsText, relative := relativeBits(spec); relative {
		bits, err := parsePrefixBits(bitsText, 64)
		if err != nil {
			return Prefix8{}, err
		}
		return Prefix8From(a, bits)
	}

	return ParsePrefix8(spec)
}

func relativeBits(spec string) (string, bool) {
	if strings.HasPrefix(spec, "/") {
		return spec[1:], true
	}
	if !strings.Contains(spec, "/") {
		return spec, true
	}
	return "", false
}

func parsePrefixBits(s string, maxBits int) (int, error) {
	if s == "" || len(s) > 3 {
		return 0, errors.New("invalid CIDR prefix length")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errors.New("invalid CIDR prefix length")
		}
		n = n*10 + int(c-'0')
	}
	if n > maxBits {
		return 0, fmt.Errorf("CIDR prefix length must be between 0 and %d", maxBits)
	}
	return n, nil
}

// normalizePrefix unmaps IPv4-mapped IPv6 prefixes (::ffff:a.b.c.d/n with
// n >= 96) to IPv4 and masks host bits.
func normalizePrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	addr, bits := p.Addr(), p.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		addr, bits = addr.Unmap(), bits-96
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}
