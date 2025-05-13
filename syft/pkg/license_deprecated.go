package pkg

import (
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

func NewLicense(value string) License {
	return NewLicenseFromType(value, license.Declared)
}

func NewLicenseFromType(value string, t license.Type) License {
	var (
		spdxExpression string
		fullText       string
	)
	// Check parsed value for newline character to see if it's the full license text
	// License: <HERE IS THE FULL TEXT> <Expressions>
	// DO we want to also submit file name when determining fulltext
	if strings.Contains(strings.TrimSpace(value), "\n") {
		fullText = value
	} else {
		var err error
		spdxExpression, err = license.ParseExpression(value)
		if err != nil {
			log.WithFields("error", err, "expression", value).Trace("unable to parse license expression")
		}
	}

	if fullText != "" {
		return License{
			Contents:  fullText,
			Type:      t,
			Locations: file.NewLocationSet(),
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
	return licenses
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
