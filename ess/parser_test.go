package ess

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestMetadataDedupNoneAndUnknownNormalization(t *testing.T) {
	db := mustTestResolver(t).current()

	if got, want := len(db.descriptions), 4; got != want {
		t.Fatalf("descriptions = %d, want %d", got, want)
	}
	if got, want := len(db.meta), 4; got != want {
		t.Fatalf("metadata records = %d, want %d", got, want)
	}
	if db.v4[1].metaID != db.v4[2].metaID {
		t.Fatalf("duplicate metadata was not deduplicated: %d != %d", db.v4[1].metaID, db.v4[2].metaID)
	}

	for _, raw := range []string{"None", "none", "nOnE", "Unknown", "unknown", " UNKNOWN "} {
		code, err := parseCountryCode([]byte(raw))
		if err != nil || code != countryNone {
			t.Fatalf("parseCountryCode(%q) = %d, %v", raw, code, err)
		}
	}
	if countryCode(countryNone) != "None" || countryName(countryNone) != "Unknown" {
		t.Fatal("countryNone semantics changed")
	}
}

// ZZ is a literal registry code, distinct from the None/Unknown sentinel.
func TestZZIsNotNone(t *testing.T) {
	code, err := parseCountryCode([]byte("zz"))
	if err != nil {
		t.Fatal(err)
	}
	if code == countryNone {
		t.Fatal("ZZ collapsed into countryNone")
	}
	if countryCode(code) != "ZZ" || countryName(code) != "Unknown" {
		t.Fatalf("ZZ = %q %q", countryCode(code), countryName(code))
	}

	r := mustLoad(t, "2.2.2.0\t2.2.2.255\t1\tZZ\tliteral\n")
	got, err := r.LookupString("2.2.2.1")
	if err != nil || got.CountryCode != "ZZ" || got.Country != "Unknown" {
		t.Fatalf("ZZ lookup = %+v, %v", got, err)
	}
}

func TestParserFormatTolerance(t *testing.T) {
	data := "# comment line\r\n" +
		"range_start\trange_end\tAS_number\tcountry_code\tAS_description\r\n" +
		"\r\n" +
		"1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET\r\n" +
		"::ffff:3.3.3.0\t::ffff:3.3.3.255\t3\tde\tmapped in TSV\n" +
		"4.4.4.0\t4.4.4.255\t4\tUS\tdesc\twith tab" // no trailing newline

	r := mustLoad(t, data)

	got, err := r.LookupString("1.1.1.1")
	if err != nil || got.Description != "CLOUDFLARENET" || got.CountryCode != "US" {
		t.Fatalf("CRLF line = %+v, %v", got, err)
	}

	got, err = r.LookupString("3.3.3.3")
	if err != nil || got.Version != 4 || got.CountryCode != "DE" {
		t.Fatalf("mapped TSV range = %+v, %v", got, err)
	}

	got, err = r.LookupString("4.4.4.4")
	if err != nil || got.Description != "desc\twith tab" {
		t.Fatalf("final line = %+v, %v", got, err)
	}

	if s := r.Stats(); s.IPv4Ranges != 3 || s.IPv6Ranges != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestParserValidation(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"bad columns", "bad\n", "expected at least 5 tab-separated columns, got 1"},
		{"four columns", "1.1.1.0\t1.1.1.255\t1\tUS\n", "got 4"},
		{"bad start", "bad\t1.1.1.1\t1\tUS\tx\n", "invalid range_start"},
		{"bad end", "1.1.1.1\tbad\t1\tUS\tx\n", "invalid range_end"},
		{"families", "1.1.1.1\t2001:db8::1\t1\tUS\tx\n", "address families differ"},
		{"bad asn", "1.1.1.0\t1.1.1.255\tx\tUS\tx\n", "invalid AS_number"},
		{"empty asn", "1.1.1.0\t1.1.1.255\t\tUS\tx\n", "invalid AS_number"},
		{"asn overflow", "1.1.1.0\t1.1.1.255\t4294967296\tUS\tx\n", "invalid AS_number"},
		{"bad country", "1.1.1.0\t1.1.1.255\t1\tUSA\tx\n", "invalid country_code"},
		{"numeric country", "1.1.1.0\t1.1.1.255\t1\t12\tx\n", "invalid country_code"},
		{"reversed v4", "1.1.1.2\t1.1.1.1\t1\tUS\tx\n", "reversed IPv4 range"},
		{"overlap v4", "1.1.1.0\t1.1.1.10\t1\tUS\tx\n1.1.1.10\t1.1.1.20\t2\tUS\ty\n", "unsorted or overlapping"},
		{"unsorted v4", "2.0.0.0\t2.0.0.255\t1\tUS\tx\n1.0.0.0\t1.0.0.255\t2\tUS\ty\n", "unsorted or overlapping"},
		{"reversed v6", "2001:db8::2\t2001:db8::1\t1\tUS\tx\n", "reversed IPv6 range"},
		{"overlap v6", "2001:db8::\t2001:db8::ff\t1\tUS\tx\n2001:db8::ff\t2001:db8::1ff\t1\tUS\tx\n", "unsorted or overlapping"},
		{"line number", "1.1.1.0\t1.1.1.255\t1\tUS\tx\nbad\n", "line 2:"},
		{"header only", "range_start\trange_end\tAS_number\tcountry_code\tAS_description\n", "no address ranges"},
		{"bad gzip", "\x1f\x8b\x00\x00", "open gzip stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

type failingReader struct {
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, "1.1.1.0\t1.1.1.255\t1\tUS\tx\n"), nil
	}
	return 0, errors.New("reader failed")
}

func TestReaderFailuresAndLineLimit(t *testing.T) {
	if _, err := Load(&failingReader{}); err == nil || err.Error() != "reader failed" {
		t.Fatalf("reader error = %v", err)
	}

	tooLong := strings.Repeat("x", maxTSVLineBytes+1)
	if _, err := Load(strings.NewReader(tooLong)); err == nil || !strings.Contains(err.Error(), "TSV line exceeds") {
		t.Fatalf("long-line error = %v", err)
	}

	// A truncated gzip stream must fail rather than load a partial database.
	full := gzipBytes(t, testTSV)
	if _, err := Load(strings.NewReader(string(full[:len(full)-6]))); err == nil {
		t.Fatal("truncated gzip loaded")
	}

	_, _ = io.Copy(io.Discard, strings.NewReader(testTSV))
}

func FuzzTSVParser(f *testing.F) {
	f.Add(testTSV)
	f.Add("1.1.1.0\t1.1.1.255\t13335\tUS\towner\n")
	f.Add("2001:db8::\t2001:db8::ff\t1\tZZ\tx\n")
	f.Add("bad")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxTSVLineBytes*2 {
			t.Skip()
		}
		r, err := Load(strings.NewReader(input))
		if err != nil {
			return
		}
		// Anything that loads must be internally consistent.
		db := r.current()
		for i := 1; i < len(db.v4); i++ {
			if db.v4[i].start <= db.v4[i-1].end {
				t.Fatalf("v4 ranges overlap at %d", i)
			}
		}
		for i := 1; i < len(db.v6); i++ {
			if compare128(db.v6[i].start, db.v6[i-1].end) <= 0 {
				t.Fatalf("v6 ranges overlap at %d", i)
			}
		}
	})
}
