package ess

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestMetadataDedupNoneAndUnknownNormalization(t *testing.T) {
	resolver := mustTestResolver(t)
	db := resolver.db

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

func TestParserValidation(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"bad columns", "bad\n", "expected at least 5 TSV columns"},
		{"bad start", "bad\t1.1.1.1\t1\tUS\tx\n", "invalid range_start"},
		{"bad end", "1.1.1.1\tbad\t1\tUS\tx\n", "invalid range_end"},
		{"families", "1.1.1.1\t2001:db8::1\t1\tUS\tx\n", "address families differ"},
		{"bad asn", "1.1.1.0\t1.1.1.255\tx\tUS\tx\n", "invalid AS_number"},
		{"bad country", "1.1.1.0\t1.1.1.255\t1\tUSA\tx\n", "invalid country_code"},
		{"reversed v4", "1.1.1.2\t1.1.1.1\t1\tUS\tx\n", "reversed IPv4 range"},
		{"overlap v4", "1.1.1.0\t1.1.1.10\t1\tUS\tx\n1.1.1.10\t1.1.1.20\t2\tUS\ty\n", "unsorted or overlapping"},
		{"reversed v6", "2001:db8::2\t2001:db8::1\t1\tUS\tx\n", "reversed IPv6 range"},
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
		copy(p, "1.1.1.0\t1.1.1.255\t1\tUS\tx\n")
		return len("1.1.1.0\t1.1.1.255\t1\tUS\tx\n"), nil
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

	_, _ = io.Copy(io.Discard, strings.NewReader(testTSV))
}

func FuzzTSVParser(f *testing.F) {
	f.Add(testTSV)
	f.Add("1.1.1.0\t1.1.1.255\t13335\tUS\towner\n")
	f.Add("bad")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxTSVLineBytes*2 {
			t.Skip()
		}
		_, _ = Load(strings.NewReader(input))
	})
}
