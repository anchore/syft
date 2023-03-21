package file

import (
	"github.com/anchore/syft/syft/license"
)

type License struct {
	Value           string
	SPDXExpression  string
	Type            license.Type
	LicenseEvidence *license.Evidence // evidence from license classifier
}

func NewLicense(value string) License {
	// TODO: validate value as an SPDX expression
	// TODO: run location against classifier to form evidence
	return License{
		Value: value,
		Type:  license.Concluded,
	}
}
