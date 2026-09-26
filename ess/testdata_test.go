package ess

import (
	"strings"
	"testing"
)

const testTSV = "" +
	"range_start\trange_end\tAS_number\tcountry_code\tAS_description\n" +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"64.23.176.0\t64.23.191.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"64.24.0.0\t64.24.0.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"100.64.0.0\t100.64.0.255\t0\tNone\tNot routed\n" +
	"2001:1948::\t2001:1948:ffff:ffff:ffff:ffff:ffff:ffff\t210\tUS\tInternet2\n"

func mustTestResolver(t testing.TB) *Resolver {
	t.Helper()

	resolver, err := Load(strings.NewReader(testTSV))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return resolver
}
