package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/andreimerlescu/naddr/ess" // naddr ess
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is main without process exit, so it can be tested.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cfg, err := parseConfig(args, getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "naddr: %v\n", err)
		return 2
	}

	if cfg.ShowVersion {
		fmt.Fprintln(stdout, BinaryVersion())
		return 0
	}

	logger := newLogger(cfg, stderr)
	slog.SetDefault(logger)

	// repository naddr
	//    package      ess
	//       func         ES
	//                       => naddr ess ES
	//                                       => n-addresses (see what I did there?)
	resolver, err := ess.ES()
	if err != nil {
		logger.Error("naddr stopped", "error", err)
		return 1
	}

	if err := runServer(cfg, resolver, logger); err != nil {
		logger.Error("naddr stopped", "error", err)
		return 1
	}

	return 0
}
