package pkg

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

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
	Value          string
	SPDXExpression string
	Type           license.Type
	URLs           []string         `hash:"ignore"`
	Locations      file.LocationSet `hash:"ignore"`
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
			log.WithFields("error", err, "expression", value).Trace("unable to parse license expression")
		}
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           t,
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
	s := strset.New()
	for _, url := range urls {
		if url != "" {
			sanitizedURL, err := stripUnwantedCharacters(url)
			if err != nil {
				log.Tracef("unable to sanitize url=%q: %s", url, err)
				continue
			}
			s.Add(sanitizedURL)
		}
	}

	l.URLs = s.List()
	sort.Strings(l.URLs)

	return l
}

func stripUnwantedCharacters(rawURL string) (string, error) {
	cleanedURL := strings.TrimSpace(rawURL)
	_, err := url.ParseRequestURI(cleanedURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return cleanedURL, nil
}

func NewLicenseFromFields(value, url string, location *file.Location) License {
	l := NewLicense(value)
	if location != nil {
		l.Locations.Add(*location)
	}
	if url != "" {
		sanitizedURL, err := stripUnwantedCharacters(url)
		if err != nil {
			log.Tracef("unable to sanitize url=%q: %s", url, err)
		} else {
			l.URLs = append(l.URLs, sanitizedURL)
		}
	}

	return l
}

// Merge two licenses into a new license object. If the merge is not possible due to unmergeable fields
// (e.g. different values for Value, SPDXExpression, Type, or any non-collection type) an error is returned.
// TODO: this is a bit of a hack to not infinitely recurse when hashing a license
func (s License) Merge(l License) (*License, error) {
	sHash, err := artifact.IDByHash(s)
	if err != nil {
		return nil, err
	}
	lHash, err := artifact.IDByHash(l)
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	// try to keep s.URLs unallocated unless necessary (which is the default state from the constructor)
	if len(l.URLs) > 0 {
		s.URLs = append(s.URLs, l.URLs...)
	}

	if len(s.URLs) > 0 {
		s.URLs = strset.New(s.URLs...).List()
		sort.Strings(s.URLs)
	}

	if l.Locations.Empty() {
		return &s, nil
	}

	// since the set instance has a reference type (map) we must make a new instance
	locations := file.NewLocationSet(s.Locations.ToSlice()...)
	locations.Add(l.Locations.ToSlice()...)
	s.Locations = locations

	return &s, nil
}
