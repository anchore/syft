package file

import (
	"github.com/anchore/syft/internal/log"
	licensepkg "github.com/anchore/syft/syft/license"
	"strings"
)

type License struct {
	Value           string
	SPDXExpression  string
	FullText        string
	Type            licensepkg.Type
	LicenseEvidence *LicenseEvidence // evidence from license classifier
}

type LicenseEvidence struct {
	Confidence int
	Offset     int
	Extent     int
}

// NewLicense creates a new syft license from pkg metadata discovered in any syft cataloger
// Note: we always use licensepkg.Concluded here given the definition provided by spdx
// Concluded: The license that the SPDX file creator believes governs the package.
// This license can be determined by the creator or by a scanning tool they use.
func NewLicense(license string) License {
	// when a metadata field contains a newline this is most likely an indicator
	// of a full text license having made it to the constructor
	// in this case we annotate this as the full text to not lose value and do not extract the complex case
	if strings.Contains(license, "\n") {
		return License{
			FullText: license,
		}
	}

	spdxExpression, err := licensepkg.ParseExpression(license)
	if err != nil {
		log.WithFields("error", err, "license", license).Trace("unable to parse license as valid spdx expression")
		return License{
			Value: license,
			Type:  licensepkg.Concluded,
		}
	}

	return License{
		Value:          license,
		SPDXExpression: spdxExpression,
		Type:           licensepkg.Concluded,
	}
}
