package license

import (
	"github.com/anchore/syft/syft/source"
)

type Type string

const (
	Declared  Type = "declared"
	Concluded Type = "concluded"
)

type PackageLicense struct {
	Value          string
	SPDXExpression string
	Type           Type
	URL            string          // external sources
	Location       source.Location // on disk declaration
}

type FileLicense struct {
	Value          string
	SPDXExpression string
	Location       source.Location // on disk declaration
	*LicenseEvidence
}

type LicenseEvidence struct {
	Confidence int
	Offset     int
	Extent     int
}

func NewPackageLicense(value string, url string, location source.Location) PackageLicense {
	// TODO: validate value as an SPDX expression
	return PackageLicense{
		Value:    value,
		URL:      url,
		Location: location,
		Type:     Declared,
	}
}

func NewFileLicense(value string, location source.Location) FileLicense {
	// TODO: validate value as an SPDX expression
	// TODO: run location against classifier to form evidence
	return FileLicense{
		Value:    value,
		Location: location,
	}
}
