package ess

import (
	"fmt"
	"os"
	"strings"
)

const (
	// DefaultDataPath is the default external IPtoASN TSV path used by ES.
	DefaultDataPath = "tsv/ip2asn-combined.tsv"

	// EnvDataPath overrides DefaultDataPath.
	EnvDataPath = "NADDR_DATA"

	// IPtoASNDataURL is the upstream compressed database URL shown in errors.
	// The ess package intentionally does not download it automatically.
	IPtoASNDataURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
)

// ES loads the default external IPtoASN database and returns its Resolver.
//
// repository nattr
//
//	package      ess
//	   func         ES
//	                   => nattr ess ES
//	                                   => nAddresses
func ES() (*Resolver, error) {
	dataPath := strings.TrimSpace(os.Getenv(EnvDataPath))
	if dataPath == "" {
		dataPath = DefaultDataPath
	}

	resolver, err := Open(dataPath)
	if err != nil {
		return nil, fmt.Errorf(
			"load IPtoASN database %q: %w; download %s, extract it, or set %s",
			dataPath,
			err,
			IPtoASNDataURL,
			EnvDataPath,
		)
	}

	return resolver, nil
}
