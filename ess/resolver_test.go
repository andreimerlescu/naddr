package ess

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestRangeStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(v4Range{}); got != 16 {
		t.Fatalf("v4Range size = %d, want 16", got)
	}
	if got := unsafe.Sizeof(v6Range{}); got != 40 {
		t.Fatalf("v6Range size = %d, want 40", got)
	}
}

func TestResolverLookupIPv4AndIPv6(t *testing.T) {
	resolver := mustTestResolver(t)

	v4, err := resolver.LookupString("45.138.12.24")
	if err != nil {
		t.Fatal(err)
	}
	if v4.Version != 4 || v4.Number != 218785 || v4.ASN != "AS218785" ||
		v4.Description != "UAB Cherry Servers" || v4.Country != "Lithuania" ||
		v4.CountryCode != "LT" || v4.Range != "45.138.12.0/24" ||
		v4.Address != netip.MustParseAddr("45.138.12.24") {
		t.Fatalf("unexpected IPv4 result: %+v", v4)
	}

	v6, err := resolver.LookupString("2001:1948:e00:1001::2")
	if err != nil {
		t.Fatal(err)
	}
	if v6.Version != 6 || v6.Number != 210 || v6.ASN != "AS210" ||
		v6.Description != "Internet2" || v6.Country != "United States" ||
		v6.CountryCode != "US" || v6.Range != "2001:1948::/32" {
		t.Fatalf("unexpected IPv6 result: %+v", v6)
	}

	none, err := resolver.LookupString("100.64.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if none.CountryCode != "None" || none.Country != "Unknown" || none.Number != 0 || none.Description != "Not routed" {
		t.Fatalf("unexpected None result: %+v", none)
	}

	if _, err := resolver.LookupString("8.8.8.8"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("missing lookup error = %v", err)
	}
	if _, err := resolver.LookupString("bad"); err == nil || err.Error() != "invalid IP address" {
		t.Fatalf("invalid lookup error = %v", err)
	}
}

func TestResolverMappedIPv4AndStats(t *testing.T) {
	resolver := mustTestResolver(t)
	got, err := resolver.LookupString("::ffff:45.138.12.24")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 4 || got.Address.String() != "45.138.12.24" {
		t.Fatalf("mapped IPv4 result: %+v", got)
	}

	stats := resolver.Stats()
	if stats.IPv4Ranges != 4 || stats.IPv6Ranges != 1 || stats.ASNMetadata != 4 || stats.Descriptions != 4 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestOpenAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn-combined.tsv")
	if err := os.WriteFile(path, []byte(testTSV), 0o600); err != nil {
		t.Fatal(err)
	}

	resolver, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolver.Lookup(netip.MustParseAddr("64.23.184.179")); !ok {
		t.Fatal("Open resolver lookup missed")
	}

	if _, err := Open(filepath.Join(t.TempDir(), "missing.tsv")); err == nil {
		t.Fatal("expected missing file error")
	}
	if _, err := Load(nil); err == nil {
		t.Fatal("expected nil reader error")
	}
	if _, err := Load(strings.NewReader("")); err == nil {
		t.Fatal("expected empty database error")
	}

	var nilResolver *Resolver
	if _, err := nilResolver.LookupString("1.1.1.1"); !errors.Is(err, ErrNilResolver) {
		t.Fatalf("nil resolver error = %v", err)
	}
}

func TestLookupAllocations(t *testing.T) {
	resolver := mustTestResolver(t)
	v4 := ipv4Uint32(netip.MustParseAddr("64.23.184.179"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := resolver.db.lookupV4(v4); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv4 lookup allocations = %f, want 0", allocs)
	}

	v6 := uint128FromAddr(netip.MustParseAddr("2001:1948:e00:1001::2"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := resolver.db.lookupV6(v6); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv6 lookup allocations = %f, want 0", allocs)
	}
}
