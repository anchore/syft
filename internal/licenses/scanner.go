package licenses

import (
	"context"
	"io"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/internal/log"
)

const coverageThreshold = 75 // determined by experimentation

type Scanner interface {
	IdentifyLicenseIDs(context.Context, io.Reader) ([]string, []byte, error)
}

var _ Scanner = (*scanner)(nil)

type scanner struct {
	coverageThreshold float64 // between 0 and 100
	scanner           func([]byte) licensecheck.Coverage
}

// NewDefaultScanner returns a scanner that uses a new instance of the default licensecheck package scanner.
func NewDefaultScanner() Scanner {
	s, err := licensecheck.NewScanner(licensecheck.BuiltinLicenses())
	if err != nil {
		log.WithFields("error", err).Trace("unable to create default license scanner")
		s = nil
	}
	return &scanner{
		coverageThreshold: coverageThreshold,
		scanner:           s.Scan,
	}
}

func (s scanner) IdentifyLicenseIDs(_ context.Context, reader io.Reader) ([]string, []byte, error) {
	if s.scanner == nil {
		return nil, nil, nil
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	cov := s.scanner(content)
	if cov.Percent < s.coverageThreshold {
		// unknown or no licenses here?
		// => return binary content
		return nil, content, nil
	}

	var ids []string
	for _, m := range cov.Match {
		ids = append(ids, m.ID)
	}
	return ids, nil, nil
}
