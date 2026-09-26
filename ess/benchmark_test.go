package ess

import (
	"net/netip"
	"os"
	"testing"
)

func BenchmarkLookupIPv4(b *testing.B) {
	resolver := mustTestResolver(b)
	target := ipv4Uint32(netip.MustParseAddr("64.23.184.179"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := resolver.db.lookupV4(target); !ok {
			b.Fatal("lookup miss")
		}
	}
}

func BenchmarkLookupIPv6(b *testing.B) {
	resolver := mustTestResolver(b)
	target := uint128FromAddr(netip.MustParseAddr("2001:1948:e00:1001::2"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := resolver.db.lookupV6(target); !ok {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		if stats := resolver.Stats(); stats.IPv4Ranges+stats.IPv6Ranges == 0 {
			b.Fatal("empty database")
		}
	}
}
