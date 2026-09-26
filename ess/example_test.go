package ess_test

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/andreimerlescu/naddr/ess"
)

const exampleTSV = "" +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"64.23.176.0\t64.23.191.255\t14061\tUS\tDIGITALOCEAN-ASN\n"

func ExampleOpen() {
	// The IPtoASN file is supplied by your program at runtime,
	// plain or gzip-compressed.
	resolver, err := ess.Open("/var/lib/naddr/ip2asn-combined.tsv.gz")
	if err != nil {
		log.Fatal(err)
	}

	result, err := resolver.LookupString("45.138.12.24")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.ASN, result.Country)
}

func ExampleES() {
	// ES reads NADDR_DATA (required) and NADDR_DATA_POLL.
	resolver, err := ess.ES()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resolver.Stats().IPv4Ranges > 0)
}

func ExampleLoad() {
	resolver, err := ess.Load(strings.NewReader(exampleTSV))
	if err != nil {
		log.Fatal(err)
	}

	stats := resolver.Stats()
	fmt.Println(stats.IPv4Ranges, stats.ASNs)
	// Output:
	// 2 2
}

func ExampleResolver_LookupString() {
	resolver, err := ess.Load(strings.NewReader(exampleTSV))
	if err != nil {
		log.Fatal(err)
	}

	result, err := resolver.LookupString("45.138.12.24")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.ASN, result.CountryCode, result.Description)
	fmt.Println(result.Range)
	fmt.Println(result.IP8)
	fmt.Println(result.IP8ASN)
	fmt.Println(result.Range8)
	fmt.Println(result.Range8ASN)
	// Output:
	// AS218785 LT UAB Cherry Servers
	// 45.138.12.0/24
	// 0.3.86.161.45.138.12.24
	// 218785.45.138.12.24
	// 0.3.86.161.45.138.12.0/56
	// 218785.45.138.12.0/24
}

func ExampleResolver_LookupString_ipv8() {
	resolver, err := ess.Load(strings.NewReader(exampleTSV))
	if err != nil {
		log.Fatal(err)
	}

	// An ASN-local host is answered at the ASN level.
	result, err := resolver.LookupString("14061.10.0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Version, result.ASN, result.CountryCode)
	fmt.Println(result.Range8)
	fmt.Println(result.Range8ASN)
	// Output:
	// 8 AS14061 US
	// 0.0.54.237.0.0.0.0/32
	// 14061.0.0.0.0/0
}

func ExampleResolver_Watch() {
	resolver, err := ess.Open("/var/lib/naddr/ip2asn-combined.tsv.gz")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = resolver.Watch(ctx, ess.WatchOptions{
			OnReload: func(s ess.Stats) { log.Printf("reloaded %d ranges", s.IPv4Ranges+s.IPv6Ranges) },
			OnError:  func(err error) { log.Printf("reload failed, still serving: %v", err) },
		})
	}()

	// ... serve lookups; they always see a complete database.
}

func ExampleParseAddr8() {
	a, err := ess.ParseAddr8("64496.192.0.2.1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(a.ASN())
	fmt.Println(a.Host())
	fmt.Println(a)
	fmt.Println(a.ASNString())
	// Output:
	// 64496
	// 192.0.2.1
	// 0.0.251.240.192.0.2.1
	// 64496.192.0.2.1
}

func ExampleCheck() {
	m, err := ess.Check("64.23.184.179", "/20")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m.Member, m.Network)

	m, err = ess.Check("218785.45.138.12.24", "218785.45.138.12.0/24")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m.Version, m.Member, m.Network)
	// Output:
	// true 64.23.176.0/20
	// 8 true 0.3.86.161.45.138.12.0/56
}
