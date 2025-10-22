package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
)

// License represents license information discovered within a file.
type License struct {
	// Value is the raw license string as found in the file.
	Value string

	// SPDXExpression is the parsed SPDX license expression if available.
	SPDXExpression string

	// Type categorizes how the license was determined (e.g., declared, concluded -- following the same semantics as SPDX).
	Type license.Type

	LicenseEvidence *LicenseEvidence

	// Contents optionally stores the full license text.
	Contents string `hash:"ignore"`
}

// LicenseEvidence contains details from license classifier analysis.
type LicenseEvidence struct {
	// Confidence is a score indicating certainty of the license match.
	Confidence int

	// Offset is the byte position where the license text begins in the file.
	Offset int

	// Extent is the length in bytes of the matched license text.
	Extent int
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
