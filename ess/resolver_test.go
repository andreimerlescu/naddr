package ess

import (
	"bytes"
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

func TestResolverLookupIPv4IPv6AndNotRouted(t *testing.T) {
	resolver := mustTestResolver(t)

	v4, err := resolver.LookupString("45.138.12.24")
	if err != nil {
		t.Fatal(err)
	}
	wantV4 := Result{
		Version:     4,
		Country:     "Lithuania",
		CountryCode: "LT",
		Number:      218785,
		ASN:         "AS218785",
		Description: "UAB Cherry Servers",
		Routed:      true,
		Address:     netip.MustParseAddr("45.138.12.24"),
		Range:       "45.138.12.0/24",
		Address8:    mustAddr8(t, "218785.45.138.12.24"),
		IP8:         "0.3.86.161.45.138.12.24",
		IP8ASN:      "218785.45.138.12.24",
		Range8:      "0.3.86.161.45.138.12.0/56",
		Range8ASN:   "218785.45.138.12.0/24",
	}
	if v4 != wantV4 {
		t.Fatalf("IPv4 =\n%+v\nwant\n%+v", v4, wantV4)
	}

	v6, err := resolver.LookupString("2001:1948:e00:1001::2")
	if err != nil {
		t.Fatal(err)
	}
	wantV6 := Result{
		Version:     6,
		Country:     "United States",
		CountryCode: "US",
		Number:      210,
		ASN:         "AS210",
		Description: "Internet2",
		Routed:      true,
		Address:     netip.MustParseAddr("2001:1948:e00:1001::2"),
		Range:       "2001:1948::/32",
	}
	if v6 != wantV6 {
		t.Fatalf("IPv6 =\n%+v\nwant\n%+v", v6, wantV6)
	}

	none, err := resolver.LookupString("100.64.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if none.CountryCode != "None" || none.Country != "Unknown" || none.Number != 0 ||
		none.Routed || none.Description != "Not routed" ||
		none.IP8 != "0.0.0.0.100.64.0.1" || none.IP8ASN != "0.100.64.0.1" ||
		none.Range8 != "0.0.0.0.100.64.0.0/56" || none.Range8ASN != "0.100.64.0.0/24" {
		t.Fatalf("not routed = %+v", none)
	}

	if _, err := resolver.LookupString("8.8.8.8"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("missing lookup error = %v", err)
	}
	if _, err := resolver.LookupString("bad"); !errors.Is(err, ErrInvalidAddress) || err.Error() != "invalid IP address" {
		t.Fatalf("invalid lookup error = %v", err)
	}
	if _, err := resolver.LookupString("fe80::1%en0"); !errors.Is(err, ErrScopedAddress) {
		t.Fatalf("scoped lookup error = %v", err)
	}
}

func TestResolverLookupIPv8(t *testing.T) {
	resolver := mustTestResolver(t)

	cases := []struct {
		in        string
		version   int
		code      string
		asn       string
		desc      string
		ip8       string
		range8    string
		range8asn string
	}{
		// Host inside the same ASN's IPv4 range: host-level answer.
		{"218785.45.138.12.24", 8, "LT", "AS218785", "UAB Cherry Servers", "0.3.86.161.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
		{"0.3.86.161.45.138.12.24", 8, "LT", "AS218785", "UAB Cherry Servers", "0.3.86.161.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
		// ASN-local host: whole-ASN answer, uniform country.
		{"14061.10.0.0.1", 8, "US", "AS14061", "DIGITALOCEAN-ASN", "0.0.54.237.10.0.0.1", "0.0.54.237.0.0.0.0/32", "14061.0.0.0.0/0"},
		// Host belongs to a different ASN in IPv4: whole-ASN answer for the prefix ASN.
		{"210.45.138.12.24", 8, "US", "AS210", "Internet2", "0.0.0.210.45.138.12.24", "0.0.0.210.0.0.0.0/32", "210.0.0.0.0/0"},
		// Prefix 0.0.0.0 is IPv4.
		{"0.0.0.0.45.138.12.24", 4, "LT", "AS218785", "UAB Cherry Servers", "0.3.86.161.45.138.12.24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := resolver.LookupString(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != tc.version || got.CountryCode != tc.code || got.ASN != tc.asn ||
				got.Description != tc.desc || got.IP8 != tc.ip8 ||
				got.Range8 != tc.range8 || got.Range8ASN != tc.range8asn || !got.Routed {
				t.Fatalf("got %+v", got)
			}
			if tc.version == 8 && (got.Address.IsValid() || got.Range != "") {
				t.Fatalf("v8 result carries IPv4 fields: %+v", got)
			}
		})
	}

	if _, err := resolver.LookupString("99999.1.2.3.4"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("unknown ASN error = %v", err)
	}
	if _, ok := resolver.LookupAddr8(Addr8{}); ok {
		t.Fatal("zero Addr8 resolved")
	}
}

func TestResolverMixedCountryASN(t *testing.T) {
	resolver := mustLoad(t, ""+
		"1.0.0.0\t1.0.0.255\t64500\tUS\tMULTI\n"+
		"2.0.0.0\t2.0.0.255\t64500\tDE\tMULTI\n")

	got, err := resolver.LookupString("64500.10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CountryCode != "None" || got.Country != "Unknown" {
		t.Fatalf("mixed-country ASN = %+v", got)
	}

	got, err = resolver.LookupString("64500.2.0.0.9")
	if err != nil || got.CountryCode != "DE" {
		t.Fatalf("host-level country = %+v, %v", got, err)
	}
}

func TestResolverDominantDescription(t *testing.T) {
	resolver := mustLoad(t, ""+
		"1.0.0.0\t1.0.0.255\t64500\tUS\tOLD NAME\n"+
		"2.0.0.0\t2.0.0.255\t64500\tUS\tNEW NAME\n"+
		"3.0.0.0\t3.0.0.255\t64500\tUS\tNEW NAME\n")

	got, err := resolver.LookupString("64500.10.0.0.1")
	if err != nil || got.Description != "NEW NAME" {
		t.Fatalf("ASN-level description = %+v, %v", got, err)
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
	if stats.IPv4Ranges != 4 || stats.IPv6Ranges != 1 || stats.ASNs != 4 ||
		stats.ASNMetadata != 4 || stats.Descriptions != 4 ||
		stats.Source != "reader" || stats.LoadedAt.IsZero() || stats.Reloads != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if !resolver.Ready() {
		t.Fatal("resolver not ready")
	}
}

func TestOpenAndLoad(t *testing.T) {
	dir := t.TempDir()

	plain := filepath.Join(dir, "ip2asn-combined.tsv")
	writeFile(t, plain, testTSV)
	resolver, err := Open(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolver.Lookup(netip.MustParseAddr("64.23.184.179")); !ok {
		t.Fatal("Open resolver lookup missed")
	}
	if resolver.Stats().Source != plain {
		t.Fatalf("source = %q", resolver.Stats().Source)
	}

	gz := filepath.Join(dir, "ip2asn-combined.tsv.gz")
	if err := os.WriteFile(gz, gzipBytes(t, testTSV), 0o600); err != nil {
		t.Fatal(err)
	}
	if resolver, err = Open(gz); err != nil {
		t.Fatalf("Open gzip: %v", err)
	}
	if _, err := resolver.LookupString("45.138.12.24"); err != nil {
		t.Fatalf("gzip lookup: %v", err)
	}

	if resolver, err = Load(bytes.NewReader(gzipBytes(t, testTSV))); err != nil {
		t.Fatalf("Load gzip: %v", err)
	}
	if !resolver.Ready() {
		t.Fatal("gzip Load not ready")
	}

	if _, err := Open(filepath.Join(dir, "missing.tsv")); err == nil {
		t.Fatal("expected missing file error")
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory error = %v", err)
	}
	if _, err := Load(nil); err == nil {
		t.Fatal("expected nil reader error")
	}
	if _, err := Load(strings.NewReader("")); err == nil {
		t.Fatal("expected empty database error")
	}
}

func TestNilAndZeroResolver(t *testing.T) {
	for name, r := range map[string]*Resolver{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := r.LookupString("1.1.1.1"); !errors.Is(err, ErrNilResolver) {
				t.Fatalf("LookupString error = %v", err)
			}
			if _, ok := r.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
				t.Fatal("Lookup succeeded")
			}
			if _, ok := r.LookupAddr8(addr8FromParts(1, 1)); ok {
				t.Fatal("LookupAddr8 succeeded")
			}
			if r.Ready() {
				t.Fatal("Ready = true")
			}
			if s := r.Stats(); s != (Stats{}) {
				t.Fatalf("Stats = %+v", s)
			}
			if err := r.Reload(); !errors.Is(err, ErrNilResolver) {
				t.Fatalf("Reload error = %v", err)
			}
		})
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.tsv")
	writeFile(t, path, testTSV)

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupString("8.8.8.8"); !errors.Is(err, ErrAddressNotFound) {
		t.Fatalf("before reload = %v", err)
	}

	writeFile(t, path, extendedTSV)
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupString("8.8.8.8"); err != nil {
		t.Fatalf("after reload = %v", err)
	}
	if s := r.Stats(); s.Reloads != 1 || s.LastReloadError != "" || s.LastReloadAttempt.IsZero() {
		t.Fatalf("stats after good reload = %+v", s)
	}

	writeFile(t, path, "garbage\n")
	if err := r.Reload(); err == nil {
		t.Fatal("bad file reloaded")
	}
	if _, err := r.LookupString("8.8.8.8"); err != nil {
		t.Fatalf("previous database lost after failed reload: %v", err)
	}
	if s := r.Stats(); s.Reloads != 1 || s.LastReloadError == "" {
		t.Fatalf("stats after bad reload = %+v", s)
	}

	if err := mustTestResolver(t).Reload(); !errors.Is(err, ErrNoSource) {
		t.Fatalf("Load-based Reload = %v", err)
	}
}

func TestLookupAllocations(t *testing.T) {
	db := mustTestResolver(t).current()

	v4 := ipv4Uint32(netip.MustParseAddr("64.23.184.179"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := db.lookupV4(v4); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv4 lookup allocations = %f, want 0", allocs)
	}

	v6 := uint128FromAddr(netip.MustParseAddr("2001:1948:e00:1001::2"))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := db.lookupV6(v6); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("IPv6 lookup allocations = %f, want 0", allocs)
	}

	if allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := db.lookupASN(14061); !ok {
			panic("miss")
		}
	}); allocs != 0 {
		t.Fatalf("ASN lookup allocations = %f, want 0", allocs)
	}
}
