# ess

Package `ess` resolves IPv4, IPv6, and draft IPv8 addresses to ASN, network description, country, and containing range, using a local copy of the IPtoASN database. No HTTP, no network calls, no bundled data.

```go
import "github.com/andreimerlescu/naddr/ess"
```

## You supply the data

`ess` does not include or download the database. Your program provides the IPtoASN combined TSV at runtime:

```text
https://iptoasn.com/data/ip2asn-combined.tsv.gz
```

The file can be used as downloaded (gzip) or extracted. Your application decides where it lives and how it is updated.

## Quick start

```go
resolver, err := ess.Open("/var/lib/myapp/ip2asn-combined.tsv.gz")
if err != nil {
	log.Fatal(err)
}

result, err := resolver.LookupString("45.138.12.24")
if err != nil {
	log.Fatal(err)
}

fmt.Println(result.ASN, result.CountryCode, result.Description, result.Range)
// AS218785 LT UAB Cherry Servers 45.138.12.0/24
```

A `Resolver` is safe for concurrent use. Create one and share it.

## Loading

| Function | Source | Can reload |
|---|---|---|
| `Open(path)` | File, plain or gzip | yes |
| `OpenConfig(cfg)` | File, with a watch interval | yes |
| `ES()` | File named by `NADDR_DATA` | yes |
| `Load(reader)` | Any `io.Reader`, plain or gzip | no |

`ES` and `ConfigFromEnv` read:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `NADDR_DATA` | yes | — | Path to the TSV, plain or `.gz` |
| `NADDR_DATA_POLL` | no | `30s` | Watch interval; minimum `1s`; `0`/`off` disables |

If you would rather not use environment variables, call `Open` or `OpenConfig` with your own configuration.

Loading validates everything and fails on the first problem:

- malformed addresses or ASNs
- address family mismatches
- invalid country codes
- reversed, unsorted, or overlapping ranges
- lines over 64 KiB
- a corrupt gzip stream
- an empty database

Bad data never becomes a serving database.

## Reloading

Each loaded database is immutable. `Reload` and `Watch` build a complete replacement, validate it, and swap it in atomically. Lookups never block and never see a half-loaded database.

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go resolver.Watch(ctx, ess.WatchOptions{
	OnReload: func(s ess.Stats) { log.Printf("reloaded: %d ranges", s.IPv4Ranges+s.IPv6Ranges) },
	OnError:  func(err error) { log.Printf("reload failed, still serving previous data: %v", err) },
})
```

How `Watch` behaves:

- **Change detection.** It compares size, modification time, and file identity, so both in-place writes and atomic `mv` replacements are detected.
- **Waiting for complete files.** A changed file is loaded only after it stays unchanged for one full interval, so partial downloads are skipped.
- **Failures.** A file that fails to load is reported through `OnError` and recorded in `Stats().LastReloadError`, and the previous database keeps serving. It is retried when the file changes again.
- **Interval.** `WatchOptions.Interval` overrides the Resolver's interval. A non-positive result disables watching (`Watch` returns `nil`).
- **Errors.** It returns `ErrNoSource` for Resolvers built with `Load`.

Call `Reload()` yourself if you prefer to trigger updates explicitly, for example on `SIGHUP`.

## Lookups

```go
resolver.LookupString("45.138.12.24")            // IPv4
resolver.LookupString("2001:1948::1")            // IPv6
resolver.LookupString("::ffff:45.138.12.24")     // normalized to IPv4
resolver.LookupString("218785.45.138.12.24")     // IPv8, ASN dot form
resolver.LookupString("0.3.86.161.45.138.12.24") // IPv8, 8-octet form

resolver.Lookup(netip.MustParseAddr("45.138.12.24"))       // (Result, bool)
resolver.LookupAddr8(addr8)                                 // (Result, bool)
```

`LookupString` errors:

| Error | Meaning |
|---|---|
| `ErrInvalidAddress` | Not an IPv4, IPv6, or IPv8 address |
| `ErrScopedAddress` | IPv6 with a zone (`fe80::1%en0`) |
| `ErrAddressNotFound` | Valid address, not in the database |
| `ErrNilResolver` | Resolver is nil or unloaded |

The IPv4 and IPv6 range lookups perform zero allocations. `LookupString` allocates only to build the Result's strings.

### Result

```go
type Result struct {
	Version     int        // 4, 6, or 8
	Country     string     // "Lithuania"
	CountryCode string     // "LT"
	Number      uint32     // 218785
	ASN         string     // "AS218785"
	Description string     // "UAB Cherry Servers"
	Routed      bool       // false for IPtoASN "Not routed" (ASN 0)
	Address     netip.Addr // IPv4/IPv6 results only
	Range       string     // "45.138.12.0/24", or "start-end" if not a CIDR
	Address8    Addr8      // IPv8 form, when present
	IP8         string     // "0.3.86.161.45.138.12.24"
	IP8ASN      string     // "218785.45.138.12.24"
	Range8      string     // "0.3.86.161.45.138.12.0/56"
	Range8ASN   string     // "218785.45.138.12.0/24"
}
```

`Result` has JSON tags; empty fields are omitted.

### Country codes

`None` and `Unknown` in the TSV mean no country was assigned. They are returned as `CountryCode: "None"`, `Country: "Unknown"`. The literal code `ZZ` is kept as `ZZ`; its name is also `Unknown`, but the code stays distinct. Codes not in the built-in table return their code with the name `Unknown`.

## IPv8

`ess` implements [draft-thain-ipv8-02](https://datatracker.ietf.org/doc/draft-thain-ipv8/), recorded in the constant `ess.IPv8Draft`.

> This is an individual Internet-Draft, not an IETF standard, and it expires on 19 October 2026 unless renewed. `ess` pins the revision and will follow format changes.

An IPv8 address is a 32-bit ASN prefix plus a 32-bit IPv4 host. The prefix `0.0.0.0` means plain IPv4.

**Version 4 results** include IPv8 fields derived from the owning ASN. **Version 6 results** never include them.

**Version 8 results** come from `LookupAddr8`, or from `LookupString` given an IPv8 address with a non-zero prefix:

1. **The host falls inside an IPv4 range assigned to the same ASN.** That range's country and bounds apply.
2. **Otherwise.** The answer covers the whole ASN:
    - `Range8` is `r.r.r.r.0.0.0.0/32`.
    - `Description` is the ASN's most common description.
    - `Country` is set only if all of the ASN's ranges agree.

Version 8 results leave `Address` and `Range` empty, because an IPv8 host address is local to its ASN, not a public IPv4 address. Case 1 is an inference (an ASN keeps its IPv4 space in IPv8); the draft defines no registry yet.

Types and helpers:

```go
a, _ := ess.ParseAddr8("64496.192.0.2.1")
a.ASN()        // 64496
a.Host()       // 192.0.2.1
a.String()     // 0.0.251.240.192.0.2.1
a.ASNString()  // 64496.192.0.2.1

ess.Addr8From(64496, netip.MustParseAddr("192.0.2.1"))

p, _ := ess.ParsePrefix8("64496.192.0.2.0/24") // host bits in ASN dot form
p.String()     // 0.0.251.240.192.0.2.0/56    (64-bit bits in 8-octet form)
p.Contains(a)  // true
```

`Addr8` is comparable and implements `encoding.TextMarshaler`.

## Membership

```go
m, err := ess.Check("64.23.184.179", "64.23.176.0/20")
// m.Version == 4, m.Member == true, m.Network == "64.23.176.0/20"

m, err = ess.Check("64.23.184.179", "/20")   // "what is this address's /20?"
// m.Network == "64.23.176.0/20"

m, err = ess.Check("218785.45.138.12.24", "218785.45.138.12.0/24")
// m.Version == 8, m.Member == true
```

A relative prefix (`/20` or `20`) is built around the address itself, so it always contains the address. Use it to find the network, not to test membership.

Lower-level helpers: `ParseAddr`, `ParseMembershipPrefix`, `ParseMembershipPrefix8`, `Contains`, `In`.

## Stats

```go
s := resolver.Stats()
// IPv4Ranges, IPv6Ranges, ASNs, ASNMetadata, Descriptions
// Source, LoadedAt, Reloads, LastReloadAttempt, LastReloadError
```

## How lookup works

At load time, IPv4 and IPv6 ranges go into separate sorted slices of compact records (16 and 40 bytes). ASN metadata and descriptions are deduplicated and referenced by ID. A 65,536-entry directory keyed on each address's top 16 bits narrows every lookup to a small slice. Binary search then finds the range. Ranges that cross a /16 boundary are handled by also checking the preceding entry.

The tests compare this index against a linear scan over thousands of random ranges and fuzz the comparison.

## Performance

```bash
go test -run='^$' -bench=. -benchmem ./ess
NADDR_DATA=/path/to/ip2asn-combined.tsv.gz go test -run='^$' -bench=BenchmarkLoadExternalDatabase -benchmem ./ess
```

Measure on the hardware you deploy to.
