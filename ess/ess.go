package ess

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// EnvDataPath names the environment variable holding the path to the
	// IPtoASN TSV file (plain or .gz). ES requires it.
	EnvDataPath = "NADDR_DATA"

	// EnvDataPoll names the environment variable controlling how often a
	// watched data file is checked for changes. It accepts a Go duration
	// ("30s", "5m") or "0"/"off" to disable watching.
	EnvDataPoll = "NADDR_DATA_POLL"

	// DefaultPollInterval is used when EnvDataPoll is unset.
	DefaultPollInterval = 30 * time.Second

	// MinPollInterval is the smallest interval accepted from EnvDataPoll.
	MinPollInterval = time.Second

	// IPtoASNDataURL is the upstream database. ess never downloads it.
	IPtoASNDataURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
)

// ErrDataPathUnset is returned when EnvDataPath is empty or unset.
var ErrDataPathUnset = errors.New(EnvDataPath + " is not set")

// Config describes where the database lives and how it is watched.
type Config struct {
	// Path is the IPtoASN TSV file, plain or gzip-compressed.
	Path string

	// PollInterval is how often Watch checks Path. Zero disables watching.
	PollInterval time.Duration
}

// ConfigFromEnv reads EnvDataPath and EnvDataPoll using getenv (os.Getenv
// when nil). EnvDataPath is required.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg := Config{
		Path:         strings.TrimSpace(getenv(EnvDataPath)),
		PollInterval: DefaultPollInterval,
	}
	if cfg.Path == "" {
		return Config{}, fmt.Errorf("%w: set it to an IPtoASN TSV file (download %s)",
			ErrDataPathUnset, IPtoASNDataURL)
	}

	raw := strings.TrimSpace(getenv(EnvDataPoll))
	switch strings.ToLower(raw) {
	case "":
	case "0", "off", "false", "disabled":
		cfg.PollInterval = 0
	default:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvDataPoll, err)
		}
		if d < MinPollInterval {
			return Config{}, fmt.Errorf("%s must be at least %s, or 0 to disable", EnvDataPoll, MinPollInterval)
		}
		cfg.PollInterval = d
	}

	return cfg, nil
}

// OpenConfig opens the database described by cfg. The returned Resolver's
// Watch uses cfg.PollInterval by default.
func OpenConfig(cfg Config) (*Resolver, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, ErrDataPathUnset
	}

	resolver, err := Open(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("%w; download %s (plain or .gz) and point %s at it",
			err, IPtoASNDataURL, EnvDataPath)
	}
	resolver.pollInterval = cfg.PollInterval

	return resolver, nil
}

// ES opens the database named by the NADDR_DATA environment variable, with
// the watch interval from NADDR_DATA_POLL.
//
//	repository naddr
//	   package      ess
//	      func         ES
//	                      => naddr ess ES
//	                                      => n-addresses
func ES() (*Resolver, error) {
	cfg, err := ConfigFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	return OpenConfig(cfg)
}
