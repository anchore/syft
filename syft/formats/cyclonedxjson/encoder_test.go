package cyclonedxjson

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateCycloneDx = flag.Bool("update-cyclonedx", false, "update the *.golden files for cyclone-dx encoders")

func TestCycloneDxDirectoryEncoder(t *testing.T) {
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		testutils.DirectoryInput(t),
		*updateCycloneDx,
		true,
		cycloneDxRedactor,
	)
}

func TestCycloneDxImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		testutils.ImageInput(t, testImage),
		testImage,
		*updateCycloneDx,
		true,
		cycloneDxRedactor,
	)
}

func cycloneDxRedactor(s []byte) []byte {
	replacements := map[string]string{
		// UUIDs
		`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`: `urn:uuid:redacted`,
		// timestamps
		`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`: `timestamp:redacted`,
		// image hashes
		`sha256:[A-Fa-f0-9]{64}`: `sha256:redacted`,
		// bom-refs
		`"bom-ref":\s*"[^"]+"`: `"bom-ref": "redacted"`,
	}
	for pattern, replacement := range replacements {
		s = regexp.MustCompile(pattern).ReplaceAll(s, []byte(replacement))
	}
	return s
}
