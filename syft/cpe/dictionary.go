package cpe

import (
	"regexp"

	"github.com/anchore/syft/syft/pkg"
)

type Dictionary interface {
	IdentifyPackageCPEs(p pkg.Package) []pkg.CPE
	Close() error
}

type SpecificCandidate struct {
	Match     regexp.Regexp
	Candidate Candidate
}

type Candidate struct {
	Term  string
	Boost float64
}
