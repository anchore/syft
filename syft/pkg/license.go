package pkg

import (
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/source"
)

type PackageLicense struct {
	Value          string
	SPDXExpression string
	Type           license.Type
	URL            string          // external sources
	Location       source.Location // on disk declaration
}

func NewPackageLicense(value string, url string, location source.Location) PackageLicense {
	// TODO: validate value as an SPDX expression
	// TODO: how do we express other places where a license is declared
	// EX: we got this from the go module cache at path /x/y/z on disk
	return PackageLicense{
		Value:    value,
		URL:      url,
		Location: location,
		Type:     license.Declared,
	}
}
