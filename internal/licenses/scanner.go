package licenses

import (
	"context"
	"fmt"
	"io"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/internal/log"
)

const (
	UnknownLicensePrefix     = unknownLicenseType + "_"
	DefaultCoverageThreshold = 75 // determined by experimentation

	unknownLicenseType = "UNKNOWN"
)

type Evidence struct {
	ID    string            // License identifier. (See licenses/README.md.)
	Type  licensecheck.Type // The type of the license: BSD, MIT, etc.
	Start int               // Start offset of match in text; match is at text[Start:End].
	End   int               // End offset of match in text.
	IsURL bool              // Whether match is a URL.
}

type Scanner interface {
	FindEvidence(context.Context, io.Reader) ([]Evidence, []byte, error)
}

var _ Scanner = (*scanner)(nil)

type scanner struct {
	coverageThreshold float64 // between 0 and 100
	scanner           func([]byte) licensecheck.Coverage
}

type ScannerConfig struct {
	CoverageThreshold float64
	Scanner           func([]byte) licensecheck.Coverage
}

type Option func(*scanner)

func WithCoverage(coverage float64) Option {
	return func(s *scanner) {
		s.coverageThreshold = coverage
	}
}

// NewDefaultScanner returns a scanner that uses a new instance of the default licensecheck package scanner.
func NewDefaultScanner(o ...Option) (Scanner, error) {
	s, err := licensecheck.NewScanner(licensecheck.BuiltinLicenses())
	if err != nil {
		log.WithFields("error", err).Trace("unable to create default license scanner")
		return nil, fmt.Errorf("unable to create default license scanner: %w", err)
	}

	newScanner := &scanner{
		coverageThreshold: DefaultCoverageThreshold,
		scanner:           s.Scan,
	}

	for _, opt := range o {
		opt(newScanner)
	}
	return newScanner, nil
}

// NewScanner generates a license Scanner with the given ScannerConfig
// if config is nil NewDefaultScanner is used
func NewScanner(c *ScannerConfig) (Scanner, error) {
	if c == nil {
		return NewDefaultScanner()
	}

	return &scanner{
		coverageThreshold: c.CoverageThreshold,
		scanner:           c.Scanner,
	}, nil
}
