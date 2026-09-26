package ess

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseAddr parses an IP address, rejects scoped IPv6 addresses, and normalizes
// IPv4-mapped IPv6 addresses to IPv4.
func ParseAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, errors.New("invalid IP address")
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errors.New("scoped IPv6 addresses are not supported")
	}
	return addr.Unmap(), nil
}

// ParseMembershipPrefix accepts ip/cidr, /cidr, or cidr forms. For the latter
// two forms the prefix is constructed around addr.
func ParseMembershipPrefix(addr netip.Addr, spec string) (netip.Prefix, error) {
	if !addr.IsValid() || addr.Zone() != "" {
		return netip.Prefix{}, errors.New("invalid IP address")
	}
	addr = addr.Unmap()
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return netip.Prefix{}, errors.New("missing in")
	}

	if strings.HasPrefix(spec, "/") {
		bitsN, err := strconv.Atoi(strings.TrimPrefix(spec, "/"))
		if err != nil {
			return netip.Prefix{}, errors.New("invalid CIDR prefix length")
		}
		return prefixFromBits(addr, bitsN)
	}

	if !strings.Contains(spec, "/") {
		bitsN, err := strconv.Atoi(spec)
		if err != nil {
			return netip.Prefix{}, errors.New("in must be ip/cidr, /cidr, or cidr")
		}
		return prefixFromBits(addr, bitsN)
	}

	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return netip.Prefix{}, errors.New("invalid CIDR")
	}
	prefixAddr := prefix.Addr().Unmap()
	if prefixAddr.Is4() != addr.Is4() {
		return netip.Prefix{}, errors.New("IP and CIDR address families differ")
	}
	return netip.PrefixFrom(prefixAddr, prefix.Bits()).Masked(), nil
}

// Contains reports whether addr is contained by prefix after normalizing
// IPv4-mapped IPv6 addresses. Different address families return false.
func Contains(addr netip.Addr, prefix netip.Prefix) bool {
	if !addr.IsValid() || !prefix.IsValid() || addr.Zone() != "" || prefix.Addr().Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	prefixAddr := prefix.Addr().Unmap()
	if addr.Is4() != prefixAddr.Is4() {
		return false
	}
	normalized := netip.PrefixFrom(prefixAddr, prefix.Bits()).Masked()
	return normalized.Contains(addr)
}

// In parses addrText and spec and reports CIDR membership in one call.
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

func prefixFromBits(addr netip.Addr, n int) (netip.Prefix, error) {
	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	}
	if n < 0 || n > maxBits {
		return netip.Prefix{}, fmt.Errorf("CIDR prefix length must be between 0 and %d", maxBits)
	}
	return netip.PrefixFrom(addr, n).Masked(), nil
}

// Backward-compatible internal names retained for package tests and HTTP code.
func parseRequestAddr(s string) (netip.Addr, error) { return ParseAddr(s) }
func parseMembershipPrefix(addr netip.Addr, spec string) (netip.Prefix, error) {
	return ParseMembershipPrefix(addr, spec)
}
