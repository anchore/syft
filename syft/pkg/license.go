package pkg

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

var _ sort.Interface = (*Licenses)(nil)

// License represents an SPDX Expression or license value extracted from a packages metadata
// We want to ignore URLs and Location since we merge these fields across equal licenses.
// A License is a unique combination of value, expression and type, where
// its sources are always considered merged and additions to the evidence
// of where it was found and how it was sourced.
// This is different from how we treat a package since we consider package paths
// in order to distinguish if packages should be kept separate
// this is different for licenses since we're only looking for evidence
// of where a license was declared/concluded for a given package
type License struct {
	Value          string             `json:"value"`
	SPDXExpression string             `json:"spdxExpression"`
	Type           license.Type       `json:"type"`
	URLs           internal.StringSet `hash:"ignore"`
	Locations      file.LocationSet   `hash:"ignore"`
}

type Licenses []License

func (l Licenses) Len() int {
	return len(l)
}

func (l Licenses) Less(i, j int) bool {
	if l[i].Value == l[j].Value {
		if l[i].SPDXExpression == l[j].SPDXExpression {
			if l[i].Type == l[j].Type {
				// While URLs and location are not exclusive fields
				// returning true here reduces the number of swaps
				// while keeping a consistent sort order of
				// the order that they appear in the list initially
				// If users in the future have preference to sorting based
				// on the slice representation of either field we can update this code
				return true
			}
			return l[i].Type < l[j].Type
		}
		return l[i].SPDXExpression < l[j].SPDXExpression
	}
	return l[i].Value < l[j].Value
}

func (l Licenses) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func NewLicense(value string) License {
	return NewLicenseFromType(value, license.Declared)
}

func NewLicenseFromType(value string, t license.Type) License {
	var spdxExpression string
	if value != "" {
		var err error
		spdxExpression, err = license.ParseExpression(value)
		if err != nil {
			log.Trace("unable to parse license expression: %w", err)
		}
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           t,
		URLs:           internal.NewStringSet(),
		Locations:      file.NewLocationSet(),
	}
}

func NewLicensesFromValues(values ...string) (licenses []License) {
	for _, v := range values {
		licenses = append(licenses, NewLicense(v))
	}
	return
}

func NewLicensesFromLocation(location file.Location, values ...string) (licenses []License) {
	for _, v := range values {
		if v == "" {
			continue
		}
		licenses = append(licenses, NewLicenseFromLocations(v, location))
	}
	return
}

func NewLicenseFromLocations(value string, locations ...file.Location) License {
	l := NewLicense(value)
	for _, loc := range locations {
		l.Locations.Add(loc)
	}
	return l
}

func NewLicenseFromURLs(value string, urls ...string) License {
	l := NewLicense(value)
	for _, u := range urls {
		if u != "" {
			l.URLs.Add(u)
		}
	}
	return l
}

func NewLicenseFromFields(value, url string, location *file.Location) License {
	l := NewLicense(value)
	if location != nil {
		l.Locations.Add(*location)
	}
	if url != "" {
		l.URLs.Add(url)
	}
	return l
}

// this is a bit of a hack to not infinitely recurse when hashing a license
func (s License) Merge(l License) (*License, error) {
	sHash, err := artifact.IDByHash(s)
	if err != nil {
		return nil, err
	}
	lHash, err := artifact.IDByHash(l)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	s.URLs.Add(l.URLs.ToSlice()...)
	if s.Locations.Empty() && l.Locations.Empty() {
		return &s, nil
	}

	s.Locations.Add(l.Locations.ToSlice()...)
	return &s, nil
}
