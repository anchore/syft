package pkg

import (
	"fmt"
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
// Licenses can either be FullText, A valid SPDXExpression, or the Value passed from the cataloger if none of the above
type License struct {
	Value          string
	SPDXExpression string
	FullText       string
	Type           license.Type
	URLs           []string         `hash:"ignore"`
	Locations      file.LocationSet `hash:"ignore"`
}

func (l License) Empty() bool {
	if l.FullText == "" && l.SPDXExpression == "" && l.Value == "" {
		return true
	}
	return false
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
	// when a metadata field contains a newline this is most likely an indicator
	// of a full text license having made it to the constructor
	// in this case we annotate this as the full text to not lose value and do not extract the complex case
	if strings.Contains(value, "\n") {
		return License{
			FullText: value,
		}
	}

	// If we can't find a valid SPDX Expression we just return the value as is
	var err error
	spdxExpression, err = license.ParseExpression(value)
	if err != nil {
		log.WithFields("error", err, "license", value).Trace("unable to parse license expression")
		return License{
			Value:     value,
			Type:      t,
			Locations: file.NewLocationSet(),
		}
	}

	return License{
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
			s.Add(url)
		}
	}

	l.URLs = s.List()
	sort.Strings(l.URLs)

	return l
}

func NewLicenseFromFields(value, url string, location *file.Location) License {
	l := NewLicense(value)
	if location != nil {
		l.Locations.Add(*location)
	}
	if url != "" {
		l.URLs = append(l.URLs, url)
	}

	return l
}

// Merge two licenses into a new license object. If the merge is not possible due to conflicting fields
// (e.g. different values for Value, SPDXExpression, Type, or any non-collection type) an error is returned.
// TODO: this is a bit of a hack to not infinitely recurse when hashing a license
func (l License) Merge(lic License) (*License, error) {
	sHash, err := artifact.IDByHash(l)
	if err != nil {
		return nil, err
	}
	lHash, err := artifact.IDByHash(lic)
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	// try to keep s.URLs unallocated unless necessary (which is the default state from the constructor)
	if len(lic.URLs) > 0 {
		l.URLs = append(l.URLs, lic.URLs...)
	}

	if len(l.URLs) > 0 {
		l.URLs = strset.New(l.URLs...).List()
		sort.Strings(l.URLs)
	}

	if lic.Locations.Empty() {
		return &l, nil
	}

	// since the set instance has a reference type (map) we must make a new instance
	locations := file.NewLocationSet(l.Locations.ToSlice()...)
	locations.Add(lic.Locations.ToSlice()...)
	l.Locations = locations

	return &l, nil
}
