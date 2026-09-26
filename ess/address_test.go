package ess

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseAddr(t *testing.T) {
	addr, err := ParseAddr(" ::ffff:64.23.184.179 ")
	if err != nil || addr.String() != "64.23.184.179" || !addr.Is4() {
		t.Fatalf("ParseAddr mapped = %v, %v", addr, err)
	}
	if _, err := ParseAddr("bad"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("invalid error = %v", err)
	}
	if _, err := ParseAddr("fe80::1%en0"); !errors.Is(err, ErrScopedAddress) {
		t.Fatalf("scoped error = %v", err)
	}
}

func TestCIDRMembership(t *testing.T) {
	cases := []struct {
		addr string
		spec string
		want bool
	}{
		{"64.23.184.179", "64.23.176.0/20", true},
		{"64.23.184.179", "/20", true},
		{"64.23.184.179", "20", true},
		{"64.23.184.179", "64.23.160.0/20", false},
		{"64.23.184.179", "::ffff:64.23.176.0/116", true},
		{"2001:1948::1", "2001:1948::/32", true},
	}
	for _, tc := range cases {
		got, err := In(tc.addr, tc.spec)
		if err != nil || got != tc.want {
			t.Fatalf("In(%q,%q) = %v, %v; want %v", tc.addr, tc.spec, got, err, tc.want)
		}
	}

	addr := netip.MustParseAddr("64.23.184.179")
	if !Contains(addr, netip.MustParsePrefix("64.23.176.0/20")) {
		t.Fatal("Contains should be true")
	}
	if !Contains(addr, netip.MustParsePrefix("::ffff:64.23.176.0/116")) {
		t.Fatal("Contains should unmap IPv4-mapped prefixes")
	}
	if Contains(addr, netip.MustParsePrefix("::ffff:0.0.0.0/80")) {
		t.Fatal("mapped prefix shorter than /96 must not match")
	}
	if Contains(addr, netip.MustParsePrefix("2001:db8::/32")) {
		t.Fatal("Contains should reject different families")
	}
	if Contains(netip.Addr{}, netip.MustParsePrefix("0.0.0.0/0")) || Contains(addr, netip.Prefix{}) {
		t.Fatal("Contains should reject invalid inputs")
	}
}

func TestCIDRErrors(t *testing.T) {
	addr := netip.MustParseAddr("64.23.184.179")
	for _, spec := range []string{"", "/x", "x", "+20", "64.23.176.0/x", "2001:db8::/32", "/33", "/1000", "::ffff:0.0.0.0/80"} {
		if _, err := ParseMembershipPrefix(addr, spec); err == nil {
			t.Fatalf("expected error for %q", spec)
		}
	}
	if _, err := ParseMembershipPrefix(netip.Addr{}, "/8"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("invalid addr error = %v", err)
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		addr    string
		spec    string
		version int
		member  bool
		network string
	}{
		{"64.23.184.179", "64.23.176.0/20", 4, true, "64.23.176.0/20"},
		{"64.23.184.179", "/20", 4, true, "64.23.176.0/20"},
		{"64.23.184.179", "64.23.160.0/20", 4, false, "64.23.160.0/20"},
		{"2001:1948::1", "2001:1948::/32", 6, true, "2001:1948::/32"},
		{"2001:1948::1", "/48", 6, true, "2001:1948::/48"},
		{"218785.45.138.12.24", "218785.45.138.12.0/24", 8, true, "0.3.86.161.45.138.12.0/56"},
		{"218785.45.138.12.24", "0.3.86.161.0.0.0.0/32", 8, true, "0.3.86.161.0.0.0.0/32"},
		{"218785.45.138.12.24", "14061.0.0.0.0/0", 8, false, "0.0.54.237.0.0.0.0/32"},
		{"0.3.86.161.45.138.12.24", "/56", 8, true, "0.3.86.161.45.138.12.0/56"},
		{"0.3.86.161.45.138.12.24", "32", 8, true, "0.3.86.161.0.0.0.0/32"},
	}
	for _, tc := range cases {
		m, err := Check(tc.addr, tc.spec)
		if err != nil {
			t.Fatalf("Check(%q,%q): %v", tc.addr, tc.spec, err)
		}
		if m.Version != tc.version || m.Member != tc.member || m.Network != tc.network {
			t.Fatalf("Check(%q,%q) = %+v", tc.addr, tc.spec, m)
		}
	}

	for _, tc := range []struct {
		addr, spec string
		is         error
	}{
		{"bad", "20", ErrInvalidAddress},
		{"fe80::1%en0", "/64", ErrScopedAddress},
		{"218785.45.138.12.24", "1.2.3.0/24", ErrInvalidPrefix8},
		{"218785.45.138.12.24", "/65", nil},
		{"218785.45.138.12.24", "", nil},
		{"1.2.3.4", "", nil},
	} {
		_, err := Check(tc.addr, tc.spec)
		if err == nil || (tc.is != nil && !errors.Is(err, tc.is)) {
			t.Fatalf("Check(%q,%q) error = %v, want %v", tc.addr, tc.spec, err, tc.is)
		}
	}

	if _, err := ParseMembershipPrefix8(Addr8{}, "/8"); !errors.Is(err, ErrInvalidAddr8) {
		t.Fatalf("invalid Addr8 error = %v", err)
	}
}

func FuzzCIDRMembership(f *testing.F) {
	for _, seed := range [][2]string{
		{"64.23.184.179", "64.23.176.0/20"},
		{"64.23.184.179", "/20"},
		{"2001:1948::1", "2001:1948::/32"},
		{"218785.45.138.12.24", "218785.45.138.12.0/24"},
		{"bad", "20"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, addr, spec string) {
		_, _ = In(addr, spec)
		m, err := Check(addr, spec)
		if err == nil && m.Network == "" {
			t.Fatalf("Check(%q,%q) succeeded without a network", addr, spec)
		}
	})
}
