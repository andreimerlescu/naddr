# naddr

A local HTTP service that tells you who owns an IP address: ASN, network description, country, and the containing range, for IPv4, IPv6, and draft IPv8.

Built for other programs on the same host to query over `127.0.0.1`. Lookups happen in memory; nothing leaves the machine.

> [!IMPORTANT]
> **naddr needs a data file at runtime, and `NADDR_DATA` must point to it.**
>
> The IPtoASN database is not bundled with naddr and naddr never downloads it. Before starting naddr, download it yourself:
>
> ```bash
> curl -fsSL -o /var/lib/naddr/ip2asn-combined.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz
> export NADDR_DATA=/var/lib/naddr/ip2asn-combined.tsv.gz
> ```
>
> The file can stay gzipped. naddr refuses to start if `NADDR_DATA` is unset or the file is invalid.
> When the file changes, naddr reloads it automatically (see [Updating the data](#updating-the-data)).

## Quick start

Requires Go 1.26+.

```bash
git clone https://github.com/andreimerlescu/naddr.git
cd naddr
make data                                   # downloads tsv/ip2asn-combined.tsv.gz
NADDR_DATA=tsv/ip2asn-combined.tsv.gz go run .
```

```bash
curl 'http://127.0.0.1:8080/ip?addr=45.138.12.24'
```

```json
{
  "error": null,
  "success": true,
  "v": 4,
  "country": "Lithuania",
  "country_code": "LT",
  "n": 218785,
  "asn": "AS218785",
  "description": "UAB Cherry Servers",
  "routed": true,
  "ip4": "45.138.12.24",
  "ip6": "",
  "ip8": "0.3.86.161.45.138.12.24",
  "ip8asn": "218785.45.138.12.24",
  "range4": "45.138.12.0/24",
  "range6": "",
  "range8": "0.3.86.161.45.138.12.0/56",
  "range8asn": "218785.45.138.12.0/24"
}
```

Values depend on the database snapshot you load.

## HTTP API

| Endpoint | Purpose | Cache-Control |
|---|---|---|
| `GET /ip?addr=<address>` | Look up an IPv4, IPv6, or IPv8 address | `public, max-age=3600` |
| `GET /my` | Look up the requester (behind a reverse proxy) | `no-store` |
| `GET /is/addr?ess=<address>&in=<network>` | Test network membership | `no-store` |
| `GET /healthz` | Process is alive | `no-store` |
| `GET /readyz` | Database is loaded, plus load and reload status | `no-store` |
| `GET /version` | Binary version and IPv8 draft revision | `no-store` |

`HEAD` works wherever `GET` does. Other methods return `405` with `Allow: GET, HEAD`.

Every response is JSON with `"error"` (`null` or a message) and `"success"`. The `/ip` and `/my` responses always contain every key shown above, so clients can depend on a fixed schema.

| Status | Meaning |
|---|---|
| `200` | Success |
| `400` | Invalid or missing input |
| `404` | Address not in the database, or unknown route |
| `405` | Method not allowed |
| `421` | `Host` header not allowed (see [Security](#security)) |
| `503` | Database not loaded |

### `/ip`

`addr` accepts:

| Input | Example | Result `v` |
|---|---|---|
| IPv4 | `45.138.12.24` | `4` |
| IPv6 | `2001:1948::1` | `6` |
| IPv4-mapped IPv6 | `::ffff:45.138.12.24` | `4` |
| IPv8, 8-octet form | `0.3.86.161.45.138.12.24` | `8` |
| IPv8, ASN dot form | `218785.45.138.12.24` | `8` |
| IPv8 with prefix `0.0.0.0` | `0.0.0.0.45.138.12.24` | `4` |

`routed` is `false` for ranges IPtoASN marks as not routed (ASN 0). Scoped IPv6 (`fe80::1%en0`) is rejected.

### `/my`

Returns the lookup for the client's address. This only works behind a reverse proxy. A local program calling `/my` directly would be looking up `127.0.0.1`, so naddr returns `400` with an explanation instead of a misleading `404`.

Proxy headers are honored only when the direct peer is a trusted proxy (loopback by default, see `NADDR_TRUSTED_PROXIES`):

- `X-Forwarded-For` is read **right to left**. The first address that is not a trusted proxy is the client. Entries further left were supplied by the client and are ignored, so a client cannot spoof its address by sending its own `X-Forwarded-For`.
- `X-Real-IP` is used only when `X-Forwarded-For` is absent.

Configure your proxy to set one of them. For nginx:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

### `/is/addr`

Tests whether `ess` is inside `in`, and returns the normalized network.

```bash
curl 'http://127.0.0.1:8080/is/addr?ess=64.23.184.179&in=64.23.176.0/20'
```

```json
{"error":null,"success":true,"v":4,"member":true,"network":"64.23.176.0/20"}
```

`success` means the request was valid. `member` is the answer.

`in` accepts a full network (`64.23.176.0/20`), or a prefix length relative to `ess` (`/20` or `20`). The relative form always contains the address; use it to ask "what is this address's /20?" and read `network`.

IPv8 works too. Use either form; ASN dot prefixes count host bits only:

```bash
curl 'http://127.0.0.1:8080/is/addr?ess=218785.45.138.12.24&in=218785.45.138.12.0/24'
# {"error":null,"success":true,"v":8,"member":true,"network":"0.3.86.161.45.138.12.0/56"}
```

Mixing address families is a `400`.

### `/readyz`

```json
{
  "error": null,
  "success": true,
  "loaded_at": "2026-09-26T21:18:20Z",
  "ipv4_ranges": 540123,
  "ipv6_ranges": 184321,
  "asns": 81234,
  "reloads": 3,
  "last_reload_error": null
}
```

`last_reload_error` is set when the most recent reload failed. naddr keeps serving the previous database in that case, so readiness stays `200`; alert on this field.

## IPv8

naddr implements IPv8 as defined in the Internet-Draft [draft-thain-ipv8-02](https://datatracker.ietf.org/doc/draft-thain-ipv8/).

> **Status:** this is an individual Internet-Draft. It is not endorsed by the IETF, has no standing in the standards process, and expires on 19 October 2026 unless renewed. naddr pins the revision it implements (`/version` reports it). If the format changes in a later revision, naddr will follow.

An IPv8 address is 64 bits: a 32-bit ASN routing prefix and a 32-bit IPv4 host, written `r.r.r.r.n.n.n.n` or in ASN dot notation `asn.n.n.n.n`. ASN 218785 encodes as `0.3.86.161`.

IPtoASN already maps IPv4 ranges to ASNs, so naddr derives IPv8 values instead of leaving placeholders:

| Field | Meaning | Example |
|---|---|---|
| `ip8` | 8-octet form | `0.3.86.161.45.138.12.24` |
| `ip8asn` | ASN dot form | `218785.45.138.12.24` |
| `range8` | 64-bit prefix length | `0.3.86.161.45.138.12.0/56` |
| `range8asn` | Host-bit prefix length | `218785.45.138.12.0/24` |

Ranges that are not exact CIDRs render as `start-end` in all four range fields.

**Which results carry IPv8 fields:**

- `v:4` results always include them. The prefix is the ASN that owns the range, and ASN 0 ("not routed") gives `0.0.0.0.n.n.n.n`, which the draft defines as plain IPv4.
- `v:6` results never do. The draft extends IPv4 only.

**Looking up an IPv8 address (`v:8`):**

The host part `n.n.n.n` belongs to the ASN in `r.r.r.r`. naddr answers in one of two ways:

1. **The host falls inside an IPv4 range that IPtoASN assigns to that same ASN.** That range's country and bounds apply. This is the ASN's public IPv4 space carried into IPv8.
2. **Anything else.** This covers private host space like `10.0.0.1`, and hosts that IPtoASN attributes to a different ASN. naddr answers for the ASN as a whole:
    - `range8` is `r.r.r.r.0.0.0.0/32`, the entire ASN block.
    - `country` is filled only if every range that ASN holds shares one country; otherwise it is `None` / `Unknown`.

`ip4` and `range4` are empty for `v:8` results. Unknown ASNs return `404`, and so do the draft's reserved prefixes: internal zones (`127.x.x.x`) and RINE (`100.x.x.x`) map to ASNs that are never allocated.

The first case is an inference: it assumes an ASN keeps its IPv4 allocations when it moves to IPv8. The draft keeps `r.r.r.r` fixed through CGNAT and translates only `n.n.n.n`, which is consistent with that, but it does not define a registry. When real IPv8 registry data exists, naddr will use it.

## Configuration

### Data (package `ess`)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `NADDR_DATA` | **yes** | — | Path to the IPtoASN TSV, plain or `.gz` |
| `NADDR_DATA_POLL` | no | `30s` | How often to check the file for changes. Minimum `1s`; `0` or `off` disables reloading |

### Binary (package `main`)

Every setting is a flag with an environment fallback. Flags win.

| Flag | Variable | Default | Meaning |
|---|---|---|---|
| `-listen` | `NADDR_LISTEN` | `127.0.0.1:8080` | Listen address |
| `-tls-cert` | `NADDR_TLS_CERT` | — | TLS certificate file; enables HTTPS with `-tls-key` |
| `-tls-key` | `NADDR_TLS_KEY` | — | TLS private key file |
| `-log-level` | `NADDR_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `NADDR_LOG_FORMAT` | `text` | `text` or `json` |
| `-access-log` | `NADDR_ACCESS_LOG` | `false` | Log each request (method, path, status, latency; never the query string) |
| `-trusted-proxies` | `NADDR_TRUSTED_PROXIES` | `loopback` | Comma-separated CIDRs/IPs, `loopback`, or `none` |
| `-allowed-hosts` | `NADDR_ALLOWED_HOSTS` | localhost names plus the listen host | `Host` header allowlist, or `*` to disable |
| `-version` | — | — | Print the version and exit |

Without TLS, naddr serves HTTP/1.1 and cleartext HTTP/2 (h2c). With TLS, it serves HTTP/1.1 and HTTP/2 over TLS 1.2+. Certificates are read at startup; restart to rotate them.

## Updating the data

IPtoASN publishes updates regularly. Replace the file and naddr picks it up within a few poll intervals. No restart is needed.

A replacement is loaded only after the file has been unchanged for one full poll interval, so naddr does not load a download that is still being written. If the new file fails validation, naddr logs the error, reports it in `/readyz`, and keeps serving the previous data. It retries when the file changes again.

Replace the file atomically: download to a temporary file in the same directory, verify it, then `mv` it into place.

```sh
#!/bin/sh
# /etc/cron.daily/naddr-data
set -eu
dir=/var/lib/naddr
tmp=$(mktemp "$dir/.ip2asn.XXXXXX")
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp" https://iptoasn.com/data/ip2asn-combined.tsv.gz
gzip -t "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$dir/ip2asn-combined.tsv.gz"
```

## Running as a service

```ini
# /etc/systemd/system/naddr.service
[Unit]
Description=naddr IP address lookup service
After=network.target

[Service]
ExecStart=/usr/local/bin/naddr
Environment=NADDR_DATA=/var/lib/naddr/ip2asn-combined.tsv.gz
Environment=NADDR_LOG_FORMAT=json
DynamicUser=yes
ReadOnlyPaths=/var/lib/naddr
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

naddr shuts down gracefully on `SIGINT` and `SIGTERM`.

## Security

- **Localhost by default.** The default listener is `127.0.0.1:8080`.
- **Host allowlist.** Requests whose `Host` header is not allowlisted get `421`. This blocks DNS-rebinding attacks, where a web page resolves its own hostname to `127.0.0.1` to reach local services. If you listen on `0.0.0.0`, set `NADDR_ALLOWED_HOSTS` to the names clients use.
- **Proxy headers need a trusted peer.** See [`/my`](#my).
- **Hardened server limits:**
    - 2 s header read timeout
    - 5 s read timeout
    - 5 s write timeout
    - 60 s idle timeout
    - 16 KiB maximum header size
- **TLS is built in.** Enable it with `-tls-cert`/`-tls-key` when naddr is reachable beyond the host, or terminate TLS at a proxy.
- **Strict data validation.** Malformed, unsorted, or overlapping data is rejected at load time. Bad data never serves.

## Using the Go package

The lookup engine is the importable package `ess`, which has no HTTP code. See [ess/README.md](ess/README.md).

```go
import "github.com/andreimerlescu/naddr/ess"
```

## Development

```bash
make test         # tests
make test-race    # tests with the race detector
make lint         # gofmt check and go vet
make bench        # benchmarks
make fuzz         # each fuzz target for FUZZTIME (default 10s)
make build        # cross-compile into bin/
make all          # lint, clean, test, test-race, build
make data         # download the IPtoASN database into tsv/
make run          # run with tsv/ data (or $NADDR_DATA)
```

Release binaries are built for linux, darwin, and windows on amd64 and arm64 with CGO disabled, named `naddr-<os>-<arch>`.

Benchmark a full load against real data:

```bash
NADDR_DATA=tsv/ip2asn-combined.tsv.gz go test -run='^$' -bench=BenchmarkLoadExternalDatabase -benchmem ./ess
```

Contributions should include a test for the behavior they change. Take particular care with:

- IPv4/IPv6 parity
- IPv4-mapped addresses
- range validation
- `None`/`Unknown` vs literal `ZZ` country codes
- zero-allocation lookups
- concurrent reload safety

## Why `ess.ES()`?

```text
repository  naddr
package     ess
function    ES

naddr ess ES  →  n-addresses
```

Say it out loud.

## Data source and license

naddr consumes the combined database from [IPtoASN](https://iptoasn.com/). The data is not part of this repository and is governed by its provider's terms; review them before redistributing it.

naddr is licensed under the Apache License 2.0.