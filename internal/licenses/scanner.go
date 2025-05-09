package licenses

import (
	"context"
	"fmt"
	"io"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	DefaultCoverageThreshold            = 75 // determined by experimentation
	DefaultIncludeUnknownLicenseContent = false
	DefaultIncludeFullText              = false
)

type ID struct {
	LicenseID string
	Offset    Offset
}

type Offset struct {
	Start, End int
}

type Scanner interface {
	IdentifyLicenseIDs(context.Context, io.Reader) ([]ID, []byte, error)
	FileSearch(context.Context, file.LocationReadCloser) ([]file.License, error)
	PkgSearch(context.Context, file.LocationReadCloser) ([]pkg.License, error)
}

var _ Scanner = (*scanner)(nil)

type scanner struct {
	coverageThreshold            float64 // between 0 and 100
	includeUnknownLicenseContent bool
	includeFullText              bool
	scanner                      func([]byte) licensecheck.Coverage
}

type ScannerConfig struct {
	CoverageThreshold            float64
	IncludeUnknownLicenseContent bool
	IncludeFullText              bool
	Scanner                      func([]byte) licensecheck.Coverage
}

type Option func(*scanner)

func WithCoverage(coverage float64) Option {
	return func(s *scanner) {
		s.coverageThreshold = coverage
	}
}

func WithIncludeUnknownLicenseContent(includeUnknownLicenseContent bool) Option {
	return func(s *scanner) {
		s.includeUnknownLicenseContent = includeUnknownLicenseContent
	}
}

func WithIncludeFullText(includeFullText bool) Option {
	return func(s *scanner) {
		s.includeFullText = includeFullText
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
		coverageThreshold:            DefaultCoverageThreshold,
		includeUnknownLicenseContent: DefaultIncludeUnknownLicenseContent,
		includeFullText:              DefaultIncludeFullText,
		scanner:                      s.Scan,
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
		coverageThreshold:            c.CoverageThreshold,
		includeFullText:              c.IncludeFullText,
		includeUnknownLicenseContent: c.IncludeUnknownLicenseContent,
		scanner:                      c.Scanner,
	}, nil
}
