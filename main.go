package main

import (
	"log/slog"
	"os"

	"github.com/andreimerlescu/naddr/ess" // nattr ess
)

func main() {
	// repository nattr
	//    package      ess
	//       func         ES
	//                       => nattr ess ES
	//                                       => nAddresses (see what I did there?)

	resolver, err := ess.ES()
	if err != nil {
		slog.Error("naddr stopped", "error", err)
		os.Exit(1)
	}

	if err := runServer(resolver); err != nil {
		slog.Error("naddr stopped", "error", err)
		os.Exit(1)
	}
}
