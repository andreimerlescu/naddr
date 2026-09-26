package ess

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

const testHeader = "range_start\trange_end\tAS_number\tcountry_code\tAS_description\n"

const testTSV = testHeader +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"64.23.176.0\t64.23.191.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"64.24.0.0\t64.24.0.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"100.64.0.0\t100.64.0.255\t0\tNone\tNot routed\n" +
	"2001:1948::\t2001:1948:ffff:ffff:ffff:ffff:ffff:ffff\t210\tUS\tInternet2\n"

// extendedTSV is testTSV plus 8.8.8.0/24, so reload tests can observe the
// change. The new range sits in sorted position: ess rejects unsorted
// input, exactly as it would reject an unsorted IPtoASN file.
const extendedTSV = testHeader +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
	"45.138.12.0\t45.138.12.255\t218785\tLT\tUAB Cherry Servers\n" +
	"64.23.176.0\t64.23.191.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"64.24.0.0\t64.24.0.255\t14061\tUS\tDIGITALOCEAN-ASN\n" +
	"100.64.0.0\t100.64.0.255\t0\tNone\tNot routed\n" +
	"2001:1948::\t2001:1948:ffff:ffff:ffff:ffff:ffff:ffff\t210\tUS\tInternet2\n"

func mustTestResolver(t testing.TB) *Resolver {
	t.Helper()
	return mustLoad(t, testTSV)
}

func mustLoad(t testing.TB, data string) *Resolver {
	t.Helper()
	r, err := Load(strings.NewReader(data))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

func mustAddr8(t testing.TB, s string) Addr8 {
	t.Helper()
	a, err := ParseAddr8(s)
	if err != nil {
		t.Fatalf("ParseAddr8(%q): %v", s, err)
	}
	return a
}

func writeFile(t testing.TB, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gzipBytes(t testing.TB, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestFixturesLoad fails fast with a clear message if a fixture is ever
// edited into an invalid state, instead of surfacing as a watch timeout.
func TestFixturesLoad(t *testing.T) {
	for name, data := range map[string]string{"testTSV": testTSV, "extendedTSV": extendedTSV} {
		if _, err := Load(strings.NewReader(data)); err != nil {
			t.Fatalf("%s does not load: %v", name, err)
		}
	}
}
