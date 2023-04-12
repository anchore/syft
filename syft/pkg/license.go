package pkg

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/source"
)

type License struct {
	Value          string
	SPDXExpression string
	Type           license.Type
	URL            string          // external sources
	Location       source.Location // on disk declaration
}

func NewLicense(value string, url string, location source.Location) License {
	// TODO: check license package for validation enhancements
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		// TODO: warn/trace error with package context?
		log.Trace("unable to parse license expression: %w", err)
	}

	// TODO: how do we express other places where a license is declared
	// EX: we got this from the go module cache at path /x/y/z on disk
	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		URL:            url,
		Location:       location,
		Type:           license.Declared,
	}
}
