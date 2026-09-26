package ess

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

const boundaryTSV = "" +
	"0.0.0.0\t0.0.0.255\t4\tUS\tfirst\n" +
	"1.0.0.0\t1.3.255.255\t1\tAU\tspans /16 buckets\n" +
	"2.0.0.5\t2.0.0.5\t2\tDE\tsingle\n" +
	"3.0.0.1\t3.0.0.9\t5\tFR\tnot a CIDR\n" +
	"255.255.255.0\t255.255.255.255\t3\tJP\tlast\n" +
	"::1:0\t::1:ffff\t6\tUS\tlow6\n" +
	"2001:db8::1\t2001:db8::9\t7\tUS\tnot a CIDR 6\n" +
	"2001:ffff::\t2002:1:ffff:ffff:ffff:ffff:ffff:ffff\t8\tUS\tspans v6 buckets\n" +
	"ffff:ffff:ffff:ffff::\tffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t9\tUS\tlast6\n"

func TestLookupBoundaries(t *testing.T) {
	r := mustLoad(t, boundaryTSV)

	cases := []struct {
		addr  string
		found bool
		rng   string
	}{
		{"0.0.0.5", true, "0.0.0.0/24"},
		{"0.0.1.0", false, ""},
		{"1.0.0.0", true, "1.0.0.0/14"},
		{"1.2.3.4", true, "1.0.0.0/14"},
		{"1.3.255.255", true, "1.0.0.0/14"},
		{"1.4.0.0", false, ""},
		{"2.0.0.4", false, ""},
		{"2.0.0.5", true, "2.0.0.5/32"},
		{"2.0.0.6", false, ""},
		{"3.0.0.5", true, "3.0.0.1-3.0.0.9"},
		{"128.0.0.0", false, ""},
		{"255.255.254.255", false, ""},
		{"255.255.255.255", true, "255.255.255.0/24"},
		{"::1:5", true, "::1:0/112"},
		{"::2:0", false, ""},
		{"2001:db8::5", true, "2001:db8::1-2001:db8::9"},
		{"2001:db8::a", false, ""},
		{"2002::1", true, "2001:ffff::-2002:1:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2002:2::", false, ""},
		{"ffff:ffff:ffff:ffff:ffff::1", true, "ffff:ffff:ffff:ffff::/64"},
	}

	for _, tc := range cases {
		got, ok := r.Lookup(netip.MustParseAddr(tc.addr))
		if ok != tc.found || (ok && got.Range != tc.rng) {
			t.Fatalf("%s => found=%v range=%q, want found=%v range=%q", tc.addr, ok, got.Range, tc.found, tc.rng)
		}
	}

	got, ok := r.Lookup(netip.MustParseAddr("3.0.0.5"))
	if !ok || got.Range8 != "0.0.0.5.3.0.0.1-0.0.0.5.3.0.0.9" || got.Range8ASN != "5.3.0.0.1-5.3.0.0.9" {
		t.Fatalf("non-CIDR IPv8 range = %+v", got)
	}
}

// TestLookupMatchesLinearScan compares the indexed lookup against a naive
// scan over thousands of random ranges, including ranges that span many
// /16 buckets and probes at every range edge.
func TestLookupMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x6e61, 0x646472))
	v4 := randomV4Ranges(rng, 3000)
	v6 := randomV6Ranges(rng, 2000)
	db := mustLoad(t, rangesTSV(v4, v6)).current()

	for i := 0; i < 5000; i++ {
		checkV4(t, db, v4, rng.Uint32())
	}
	for _, r := range v4 {
		checkV4(t, db, v4, r[0])
		checkV4(t, db, v4, r[1])
		if r[0] > 0 {
			checkV4(t, db, v4, r[0]-1)
		}
		if r[1] < math.MaxUint32 {
			checkV4(t, db, v4, r[1]+1)
		}
	}

	limit := v6[len(v6)-1][1].hi + 1<<50
	for i := 0; i < 5000; i++ {
		checkV6(t, db, v6, uint128{hi: rng.Uint64N(limit), lo: rng.Uint64()})
	}
	for _, r := range v6 {
		checkV6(t, db, v6, r[0])
		checkV6(t, db, v6, r[1])
		if r[0].lo > 0 {
			checkV6(t, db, v6, uint128{hi: r[0].hi, lo: r[0].lo - 1})
		}
		if r[1].lo < math.MaxUint64 {
			checkV6(t, db, v6, uint128{hi: r[1].hi, lo: r[1].lo + 1})
		}
	}
}

func FuzzLookupDifferential(f *testing.F) {
	rng := rand.New(rand.NewPCG(7, 11))
	v4 := randomV4Ranges(rng, 500)
	v6 := randomV6Ranges(rng, 500)
	db := mustLoad(f, rangesTSV(v4, v6)).current()

	f.Add(uint32(0), uint64(0), uint64(0))
	f.Add(v4[0][0], v6[0][0].hi, v6[0][0].lo)
	f.Add(v4[len(v4)-1][1], v6[len(v6)-1][1].hi, v6[len(v6)-1][1].lo)

	f.Fuzz(func(t *testing.T, a uint32, hi, lo uint64) {
		checkV4(t, db, v4, a)
		checkV6(t, db, v6, uint128{hi: hi, lo: lo})
	})
}

func checkV4(t testing.TB, db *database, ranges [][2]uint32, a uint32) {
	t.Helper()
	got, ok := db.lookupV4(a)
	idx, want := linearV4(ranges, a)
	if ok != want {
		t.Fatalf("lookupV4(%s) found=%v, linear found=%v", ipv4Addr(a), ok, want)
	}
	if ok && got.start != ranges[idx][0] {
		t.Fatalf("lookupV4(%s) start=%s, linear start=%s", ipv4Addr(a), ipv4Addr(got.start), ipv4Addr(ranges[idx][0]))
	}
}

func checkV6(t testing.TB, db *database, ranges [][2]uint128, a uint128) {
	t.Helper()
	got, ok := db.lookupV6(a)
	idx, want := linearV6(ranges, a)
	if ok != want {
		t.Fatalf("lookupV6(%s) found=%v, linear found=%v", a.addr(), ok, want)
	}
	if ok && got.start != ranges[idx][0] {
		t.Fatalf("lookupV6(%s) start=%s, linear start=%s", a.addr(), got.start.addr(), ranges[idx][0].addr())
	}
}

func linearV4(ranges [][2]uint32, a uint32) (int, bool) {
	for i, r := range ranges {
		if a >= r[0] && a <= r[1] {
			return i, true
		}
	}
	return -1, false
}

func linearV6(ranges [][2]uint128, a uint128) (int, bool) {
	for i, r := range ranges {
		if compare128(a, r[0]) >= 0 && compare128(a, r[1]) <= 0 {
			return i, true
		}
	}
	return -1, false
}

// randomV4Ranges returns sorted, non-overlapping ranges of mixed sizes.
func randomV4Ranges(rng *rand.Rand, n int) [][2]uint32 {
	out := make([][2]uint32, 0, n)
	cursor := rng.Uint64N(1 << 16)

	for len(out) < n {
		start := cursor + rng.Uint64N(1<<21)
		if start > math.MaxUint32 {
			break
		}

		var length uint64
		switch rng.IntN(4) {
		case 0:
			length = 1 + rng.Uint64N(256)
		case 1:
			length = 1 + rng.Uint64N(1<<16)
		case 2:
			length = 1 + rng.Uint64N(1<<20) // crosses many /16 buckets
		default:
			length = uint64(1) << (8 + rng.IntN(9))
		}

		end := min(start+length-1, uint64(math.MaxUint32))
		out = append(out, [2]uint32{uint32(start), uint32(end)})
		if end == math.MaxUint32 {
			break
		}
		cursor = end + 1
	}
	return out
}

// randomV6Ranges returns sorted, non-overlapping ranges, some within a
// single /64 and some spanning several /16 buckets.
func randomV6Ranges(rng *rand.Rand, n int) [][2]uint128 {
	out := make([][2]uint128, 0, n)
	cursor := uint64(1) << 40 // keeps clear of ::/64 and IPv4-mapped space

	for len(out) < n {
		startHi := cursor + rng.Uint64N(1<<50)
		if startHi < cursor {
			break
		}
		start := uint128{hi: startHi, lo: rng.Uint64()}
		end := start

		if rng.IntN(3) == 0 {
			end.lo = start.lo + rng.Uint64N(max(math.MaxUint64-start.lo, 1))
		} else {
			end.hi = startHi + 1 + rng.Uint64N(1<<50)
			if end.hi < startHi {
				break
			}
			end.lo = rng.Uint64()
		}

		out = append(out, [2]uint128{start, end})
		cursor = end.hi + 1
		if cursor == 0 {
			break
		}
	}
	return out
}

func rangesTSV(v4 [][2]uint32, v6 [][2]uint128) string {
	var b strings.Builder
	for i, r := range v4 {
		asn := i%97 + 1
		fmt.Fprintf(&b, "%s\t%s\t%d\tUS\tnet-%d\n", ipv4Addr(r[0]), ipv4Addr(r[1]), asn, asn)
	}
	for i, r := range v6 {
		asn := i%89 + 1000
		fmt.Fprintf(&b, "%s\t%s\t%d\tDE\tnet6-%d\n", r[0].addr(), r[1].addr(), asn, asn)
	}
	return b.String()
}
