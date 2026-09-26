// Package ess resolves IPv4, IPv6, and draft IPv8 addresses to their
// Autonomous System, country, and containing network, using a local copy of
// the IPtoASN database.
//
// # Data dependency
//
// ess ships no data and never downloads any. Every Resolver is built from
// the IPtoASN combined TSV (https://iptoasn.com/data/ip2asn-combined.tsv.gz),
// which the importing program supplies at runtime:
//
//	resolver, err := ess.Open("/var/lib/naddr/ip2asn-combined.tsv.gz")
//
// Open and Load accept the file plain or gzip-compressed. ES reads the path
// from the NADDR_DATA environment variable, which it requires.
//
// # Concurrency and reloading
//
// A Resolver is safe for concurrent use. Each loaded database is immutable.
// Reload and Watch build a complete replacement, validate it, and swap it in
// atomically, so lookups never block and never see a partial database. A
// replacement that fails to load is discarded and the previous database
// keeps serving.
//
// # IPv8
//
// IPv8 support follows the Internet-Draft named by IPv8Draft. An IPv8
// address is a 32-bit ASN routing prefix followed by a 32-bit IPv4 host
// (r.r.r.r.n.n.n.n). Because IPtoASN maps IPv4 ranges to ASNs, every IPv4
// Result carries its derived IPv8 form. The draft is not an IETF standard;
// the package README documents exactly what ess derives and what it infers.
package ess
