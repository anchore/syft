package pkg

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/source"
)

type License struct {
	Value          string           `json:"value"`
	SPDXExpression string           `json:"spdx-expression"`
	Type           license.Type     `json:"type"`
	URL            string           `json:"url"`                // external sources
	Location       *source.Location `json:"location,omitempty"` // on disk declaration
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
