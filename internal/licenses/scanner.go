package licenses

import (
	"context"
	"io"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/internal/log"
)

const DefaultCoverageThreshold = 75 // determined by experimentation

type Scanner interface {
	IdentifyLicenseIDs(context.Context, io.Reader) ([]string, []byte, error)
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
func NewDefaultScanner(o ...Option) Scanner {
	s, err := licensecheck.NewScanner(licensecheck.BuiltinLicenses())
	if err != nil {
		log.WithFields("error", err).Trace("unable to create default license scanner")
		s = nil
	}
	newScanner := &scanner{
		coverageThreshold: DefaultCoverageThreshold,
		scanner:           s.Scan,
	}
	for _, opt := range o {
		opt(newScanner)
	}
	return newScanner
}

// NewScanner generates a license Scanner with the given ScannerConfig
// if config is nil NewDefaultScanner is used
func NewScanner(c *ScannerConfig) Scanner {
	if c == nil {
		return NewDefaultScanner()
	}

	return &scanner{
		coverageThreshold: c.CoverageThreshold,
		scanner:           c.Scanner,
	}
}

func (s *scanner) IdentifyLicenseIDs(_ context.Context, reader io.Reader) ([]string, []byte, error) {
	if s.scanner == nil {
		return nil, nil, nil
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	cov := s.scanner(content)
	if cov.Percent < s.coverageThreshold {
		// unknown or no licenses here
		// => check return content to Search to process
		return nil, content, nil
	}

	var ids []string
	for _, m := range cov.Match {
		ids = append(ids, m.ID)
	}
	return ids, nil, nil
}
