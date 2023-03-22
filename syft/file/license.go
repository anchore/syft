package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
)

type License struct {
	Value           string
	SPDXExpression  string
	Type            license.Type
	LicenseEvidence *license.Evidence // evidence from license classifier
}

func NewLicense(value string) License {
	// TODO: enhance license package with more helpers for validation
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		log.Trace("unable to parse license expression: %w", err)
	}

	// TODO: run location against classifier to form evidence
	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           license.Concluded,
	}
}
