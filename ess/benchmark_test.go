package ess

import (
	"net/netip"
	"os"
	"testing"
)

func BenchmarkLookupIPv4(b *testing.B) {
	db := mustTestResolver(b).current()
	target := ipv4Uint32(netip.MustParseAddr("64.23.184.179"))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := db.lookupV4(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

func BenchmarkLookupIPv6(b *testing.B) {
	db := mustTestResolver(b).current()
	target := uint128FromAddr(netip.MustParseAddr("2001:1948:e00:1001::2"))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := db.lookupV6(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

// BenchmarkLookupString measures the full public path: parsing, lookup,
// and building the Result, including IPv8 derivation.
func BenchmarkLookupString(b *testing.B) {
	resolver := mustTestResolver(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := resolver.LookupString("64.23.184.179"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLookupAddr8(b *testing.B) {
	resolver := mustTestResolver(b)
	target := mustAddr8(b, "14061.10.0.0.1")
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := resolver.LookupAddr8(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

func BenchmarkLoadExternalDatabase(b *testing.B) {
	path := os.Getenv(EnvDataPath)
	if path == "" {
		b.Skipf("set %s to benchmark the full external database", EnvDataPath)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	for b.Loop() {
		resolver, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		if !resolver.Ready() {
			b.Fatal("empty database")
		}
	}
}
