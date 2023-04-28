package pkg

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/source"
)

var _ sort.Interface = (*Licenses)(nil)

type License struct {
	Value          string           `json:"value"`
	SPDXExpression string           `json:"spdxExpression"`
	Type           license.Type     `json:"type"`
	URL            string           `json:"url"`                // external sources
	Location       *source.Location `json:"location,omitempty"` // on disk declaration
}

type Licenses []License

func (l Licenses) Len() int {
	return len(l)
}

func (l Licenses) Less(i, j int) bool {
	if l[i].Value == l[j].Value {
		if l[i].SPDXExpression == l[j].SPDXExpression {
			if l[i].Type == l[j].Type {
				if l[i].URL == l[j].URL {
					if l[i].Location == nil && l[j].Location == nil {
						return false
					}
					if l[i].Location == nil {
						return true
					}
					if l[j].Location == nil {
						return false
					}
					sl := source.Locations{*l[i].Location, *l[j].Location}
					return sl.Less(0, 1)
				}
				return l[i].URL < l[j].URL
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
	}
}

func NewLicensesFromValues(values ...string) (licenses []License) {
	for _, v := range values {
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
		licenses = append(licenses, NewLicenseFromLocation(v, location))
	}
	return
}

func NewLicenseFromLocation(value string, location source.Location) License {
	l := NewLicense(value)
	l.Location = &location
	return l
}

func NewLicensesFromURL(url string, values ...string) (licenses []License) {
	for _, v := range values {
		if v == "" {
			continue
		}
		licenses = append(licenses, NewLicenseFromURL(v, url))
	}
	return
}

func NewLicenseFromURL(value string, url string) License {
	l := NewLicense(value)
	l.URL = url
	return l
}

// this is a bit of a hack to not infinitely recurse when hashing a license
type noLayerLicense License

func (s License) Hash() (uint64, error) {
	if s.Location != nil {
		l := *s.Location
		// much like the location set hash function, we should not consider the file system ID when hashing
		// so that licenses found in different layers (at the same path) are not considered different.
		l.FileSystemID = ""
		s.Location = &l
	}

	return hashstructure.Hash(noLayerLicense(s), hashstructure.FormatV2,
		&hashstructure.HashOptions{
			ZeroNil:      true,
			SlicesAsSets: true,
		},
	)
}
