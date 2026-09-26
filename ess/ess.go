package ess

import (
	"log/slog"
	"os"
)

const (
	// DefaultDataPath is the default external IPtoASN TSV path used by ES.
	DefaultDataPath = "tsv/ip2asn-combined.tsv"

	// DefaultListenAddr is the default HTTP listen address used by ES.
	DefaultListenAddr = "127.0.0.1:8080"

	// EnvDataPath overrides DefaultDataPath for the naddr server.
	EnvDataPath = "NADDR_DATA"

	// EnvListenAddr overrides DefaultListenAddr for the naddr server.
	EnvListenAddr = "NADDR_LISTEN"

	// IPtoASNDataURL is the upstream compressed database URL shown in errors.
	// The ess package intentionally does not download it automatically.
	IPtoASNDataURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
)

var (
	getenv         = os.Getenv
	exitProcess    = os.Exit
	runApplication = runServer
)

// ES is intentionally the only function called by main().
//
// repository nattr
//
//	package      ess
//	   func         ES
//	                   => nattr ess ES
//	                                   => nAddresses
func ES() {
	if err := runApplication(); err != nil {
		slog.Error("naddr stopped", "error", err)
		exitProcess(1)
	}
}
