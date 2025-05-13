package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
)

type License struct {
	Value           string
	SPDXExpression  string
	Type            license.Type
	LicenseEvidence *LicenseEvidence // evidence from license classifier
	Contents        string           `hash:"ignore"`
}

type LicenseEvidence struct {
	Confidence int
	Offset     int
	Extent     int
}

func NewLicense(value string) License {
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		log.WithFields("error", err, "value", value).Trace("unable to parse license expression")
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           license.Concluded,
	}
}
