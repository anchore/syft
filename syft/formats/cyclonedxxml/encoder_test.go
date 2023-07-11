package cyclonedxxml

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateSnapshot = flag.Bool("update-cyclonedx-xml", false, "update the *.golden files for cyclone-dx XML encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestCycloneDxDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInput(t, dir),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(dir),
		},
	)
}

func TestCycloneDxImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.ImageInput(t, testImage),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(),
		},
	)
}

func redactor(values ...string) testutils.Redactor {
	return testutils.NewRedactions().
		WithValuesRedacted(values...).
		WithPatternRedactors(
			map[string]string{
				// serial numbers
				`serialNumber="[a-zA-Z0-9\-:]+`: `serialNumber="redacted`,

				// dates
				`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`: `redacted`,

				// image hashes
				`sha256:[A-Za-z0-9]{64}`: `sha256:redacted`,

				// BOM refs
				`bom-ref="[a-zA-Z0-9\-:]+"`: `bom-ref:redacted`,
			},
		)
}
