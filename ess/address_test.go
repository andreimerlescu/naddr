package ess

import (
	"net/netip"
	"testing"
)

func TestParseAddr(t *testing.T) {
	addr, err := ParseAddr(" ::ffff:64.23.184.179 ")
	if err != nil || addr.String() != "64.23.184.179" || !addr.Is4() {
		t.Fatalf("ParseAddr mapped = %v, %v", addr, err)
	}
	if _, err := ParseAddr("bad"); err == nil {
		t.Fatal("expected invalid IP error")
	}
	if _, err := ParseAddr("fe80::1%en0"); err == nil {
		t.Fatal("expected scoped IPv6 error")
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
	if Contains(addr, netip.MustParsePrefix("2001:db8::/32")) {
		t.Fatal("Contains should reject different families")
	}
}

func TestCIDRErrors(t *testing.T) {
	addr := netip.MustParseAddr("64.23.184.179")
	for _, spec := range []string{"", "/x", "x", "64.23.176.0/x", "2001:db8::/32", "/33"} {
		if _, err := ParseMembershipPrefix(addr, spec); err == nil {
			t.Fatalf("expected error for %q", spec)
		}
	}
}

func FuzzCIDRMembership(f *testing.F) {
	for _, seed := range [][2]string{
		{"64.23.184.179", "64.23.176.0/20"},
		{"64.23.184.179", "/20"},
		{"2001:1948::1", "2001:1948::/32"},
		{"bad", "20"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, addr, spec string) {
		_, _ = In(addr, spec)
	})
}
