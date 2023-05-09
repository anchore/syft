package pkg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/source"
)

var _ sort.Interface = (*Licenses)(nil)

type License struct {
	Value          string       `json:"value"`
	SPDXExpression string       `json:"spdxExpression"`
	Type           license.Type `json:"type"`
	URL            internal.StringSet
	Location       source.LocationSet
}

type Licenses []License

func (l Licenses) Len() int {
	return len(l)
}

func (l Licenses) Less(i, j int) bool {
	if l[i].Value == l[j].Value {
		if l[i].SPDXExpression == l[j].SPDXExpression {
			if l[i].Type == l[j].Type {
				// While URL and location are not exclusive fields
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
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		log.Trace("unable to parse license expression: %w", err)
	}

	// TODO: how do we express other places where a license is declared
	// EX: we got this from the go module cache at path /x/y/z on disk
	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           license.Declared,
		URL:            internal.NewStringSet(),
		Location:       source.NewLocationSet(),
	}
}

func NewLicensesFromValues(values ...string) (licenses []License) {
	for _, v := range values {
		// ignore common SPDX license expression connectors
		// that could be included in input
		if v == "" || v == "AND" {
			continue
		}
		licenses = append(licenses, NewLicense(v))
	}
	return
}

func NewLicensesFromLocation(location source.Location, values ...string) (licenses []License) {
	for _, v := range values {
		if v == "" {
			continue
		}
		licenses = append(licenses, NewLicenseFromLocations(v, location))
	}
	return
}

func NewLicenseFromLocations(value string, locations ...source.Location) License {
	l := NewLicense(value)
	for _, loc := range locations {
		l.Location.Add(loc)
	}
	return l
}

func LicenseFromURLs(value string, urls ...string) License {
	l := NewLicense(value)
	for _, u := range urls {
		if u != "" {
			l.URL.Add(u)
		}
	}
	return l
}

// this is a bit of a hack to not infinitely recurse when hashing a license
type noLayerLicense License

func (s License) Hash() (uint64, error) {
	// we want to ignore URL and location sets since we will always merge these fields
	s.URL = internal.NewStringSet()
	s.Location = source.NewLocationSet()

	return hashstructure.Hash(noLayerLicense(s), hashstructure.FormatV2,
		&hashstructure.HashOptions{
			ZeroNil:      true,
			SlicesAsSets: true,
		},
	)
}

func (s License) Merge(l License) (*License, error) {
	sHash, err := s.Hash()
	if err != nil {
		return nil, err
	}
	lHash, err := l.Hash()
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	for _, u := range l.URL.ToSlice() {
		s.URL.Add(u)
	}

	for _, l := range l.Location.ToSlice() {
		s.Location.Add(l)
	}

	return &s, nil
}
