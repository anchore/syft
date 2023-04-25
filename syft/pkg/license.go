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
	URL            string           `json:"url"`      // external sources
	Location       *source.Location `json:"location,omitempty"` // on disk declaration
}

func NewLicense(value string, url string, location *source.Location) License {
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
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
