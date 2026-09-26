package ess

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseAddr8DraftExamples(t *testing.T) {
	// draft-thain-ipv8-02 §4.4 and §7: ASN 64496 = 0.0.251.240.
	asnDot := mustAddr8(t, "64496.192.0.2.1")
	octets := mustAddr8(t, "0.0.251.240.192.0.2.1")

	if asnDot != octets {
		t.Fatalf("forms differ: %v vs %v", asnDot, octets)
	}
	if asnDot.ASN() != 64496 || asnDot.Host() != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("parts = %d %v", asnDot.ASN(), asnDot.Host())
	}
	if asnDot.String() != "0.0.251.240.192.0.2.1" || asnDot.ASNString() != "64496.192.0.2.1" {
		t.Fatalf("formatting = %q %q", asnDot.String(), asnDot.ASNString())
	}
	if asnDot.IsIPv4Compatible() {
		t.Fatal("non-zero prefix reported IPv4-compatible")
	}

	if v4 := mustAddr8(t, "0.0.0.0.192.0.2.1"); !v4.IsIPv4Compatible() || v4.ASNString() != "0.192.0.2.1" {
		t.Fatalf("IPv4-compatible = %v", v4)
	}

	if top := mustAddr8(t, "4294967295.1.2.3.4"); top.String() != "255.255.255.255.1.2.3.4" {
		t.Fatalf("max ASN = %v", top)
	}

	if a := mustAddr8(t, "  218785.45.138.12.24 "); a.String() != "0.3.86.161.45.138.12.24" {
		t.Fatalf("trimmed = %v", a)
	}
}

func TestParseAddr8Invalid(t *testing.T) {
	for _, s := range []string{
		"", "1.2.3.4", "1.2.3.4.5.6.7", "1.2.3.4.5.6.7.8.9",
		"256.0.0.0.0.0.0.0", "01.0.0.0.0.0.0.0", "1.2.3.4.5.6.7.08",
		"4294967296.1.2.3.4", "01.1.2.3.4", "-1.1.2.3.4", "+1.1.2.3.4",
		"1.2.3.4.5a", "a.b.c.d.e", "1..2.3.4", "1.2.3.4.256", "2001:db8::1",
	} {
		if _, err := ParseAddr8(s); !errors.Is(err, ErrInvalidAddr8) {
			t.Fatalf("ParseAddr8(%q) error = %v", s, err)
		}
	}
}

func TestAddr8From(t *testing.T) {
	a, err := Addr8From(64496, netip.MustParseAddr("::ffff:192.0.2.1"))
	if err != nil || a.String() != "0.0.251.240.192.0.2.1" {
		t.Fatalf("mapped host = %v, %v", a, err)
	}
	if _, err := Addr8From(1, netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("IPv6 host accepted")
	}
	if _, err := Addr8From(1, netip.Addr{}); err == nil {
		t.Fatal("invalid host accepted")
	}
}

func TestAddr8ZeroValue(t *testing.T) {
	var zero Addr8
	if zero.IsValid() || !zero.IsZero() || zero.Host().IsValid() || zero.IsIPv4Compatible() {
		t.Fatal("zero Addr8 misbehaves")
	}
	if zero.String() != "invalid IPv8" || zero.ASNString() != "invalid IPv8" {
		t.Fatalf("zero strings = %q %q", zero.String(), zero.ASNString())
	}
	if all := mustAddr8(t, "0.0.0.0.0.0.0.0"); all.IsZero() || !all.IsValid() {
		t.Fatal("0.0.0.0.0.0.0.0 must be a valid address, not the zero value")
	}
}

func TestAddr8Text(t *testing.T) {
	a := mustAddr8(t, "218785.45.138.12.24")
	b, err := a.MarshalText()
	if err != nil || string(b) != "0.3.86.161.45.138.12.24" {
		t.Fatalf("MarshalText = %q, %v", b, err)
	}

	var back Addr8
	if err := back.UnmarshalText(b); err != nil || back != a {
		t.Fatalf("UnmarshalText = %v, %v", back, err)
	}
	if err := back.UnmarshalText(nil); err != nil || back.IsValid() {
		t.Fatalf("empty UnmarshalText = %v, %v", back, err)
	}
	if err := back.UnmarshalText([]byte("nope")); err == nil {
		t.Fatal("bad UnmarshalText accepted")
	}
	if b, _ := (Addr8{}).MarshalText(); len(b) != 0 {
		t.Fatalf("zero MarshalText = %q", b)
	}
}

func TestPrefix8(t *testing.T) {
	cases := []struct {
		in       string
		str      string
		asnStr   string
		contains string
		excludes string
	}{
		{"218785.45.138.12.0/24", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24", "218785.45.138.12.200", "218785.45.138.13.0"},
		{"0.3.86.161.45.138.12.99/56", "0.3.86.161.45.138.12.0/56", "218785.45.138.12.0/24", "0.3.86.161.45.138.12.1", "14061.45.138.12.1"},
		{"14061.0.0.0.0/0", "0.0.54.237.0.0.0.0/32", "14061.0.0.0.0/0", "14061.255.255.255.255", "14062.0.0.0.0"},
		{"0.0.0.0.0.0.0.0/0", "0.0.0.0.0.0.0.0/0", "", "4294967295.1.1.1.1", ""},
		{"0.0.0.0.0.0.0.0/64", "0.0.0.0.0.0.0.0/64", "0.0.0.0.0/32", "0.0.0.0.0.0.0.0", "0.0.0.0.0.0.0.1"},
	}

	for _, tc := range cases {
		p, err := ParsePrefix8(tc.in)
		if err != nil {
			t.Fatalf("ParsePrefix8(%q): %v", tc.in, err)
		}
		if p.String() != tc.str || p.ASNString() != tc.asnStr {
			t.Fatalf("%q => %q %q", tc.in, p.String(), p.ASNString())
		}
		if !p.Contains(mustAddr8(t, tc.contains)) {
			t.Fatalf("%q should contain %q", tc.in, tc.contains)
		}
		if tc.excludes != "" && p.Contains(mustAddr8(t, tc.excludes)) {
			t.Fatalf("%q should not contain %q", tc.in, tc.excludes)
		}
	}

	for _, s := range []string{"", "1.2.3.4.5", "1.2.3.4.5/33", "0.0.0.0.0.0.0.0/65", "1.2.3.0/24", "1.2.3.4.5/x", "1.2.3.4.5/-1"} {
		if _, err := ParsePrefix8(s); err == nil {
			t.Fatalf("ParsePrefix8(%q) accepted", s)
		}
	}

	if _, err := Prefix8From(Addr8{}, 8); !errors.Is(err, ErrInvalidPrefix8) {
		t.Fatalf("invalid addr prefix error = %v", err)
	}
	var zero Prefix8
	if zero.IsValid() || zero.Contains(mustAddr8(t, "1.1.1.1.1")) || zero.String() != "invalid IPv8 prefix" {
		t.Fatal("zero Prefix8 misbehaves")
	}
}

func FuzzParseAddr8(f *testing.F) {
	for _, s := range []string{"64496.192.0.2.1", "0.0.251.240.192.0.2.1", "0.0.0.0.0.0.0.0", "bad"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAddr8(s)
		if err != nil {
			return
		}
		octets, err := ParseAddr8(a.String())
		if err != nil || octets != a {
			t.Fatalf("String round trip %q -> %q: %v", s, a.String(), err)
		}
		asnDot, err := ParseAddr8(a.ASNString())
		if err != nil || asnDot != a {
			t.Fatalf("ASNString round trip %q -> %q: %v", s, a.ASNString(), err)
		}
	})
}
