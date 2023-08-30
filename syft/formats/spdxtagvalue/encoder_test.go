package spdxtagvalue

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var updateSnapshot = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestSPDXTagValueDirectoryEncoder(t *testing.T) {
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

func TestSPDXTagValueImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(),
		},
	)
}

func TestSPDXJSONSPDXIDs(t *testing.T) {
	var pkgs []pkg.Package
	for _, name := range []string{"some/slashes", "@at-sign", "under_scores"} {
		p := pkg.Package{
			Name: name,
		}
		p.SetID()
		pkgs = append(pkgs, p)
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(pkgs...),
		},
		Relationships: nil,
		Source: source.Description{
			Name:     "foobar/baz", // in this case, foobar is used as the spdx document name
			Metadata: source.DirectorySourceMetadata{},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(),
		},
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"
	s := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AddSampleFileRelationships(&s)

	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     s,
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
				// each SBOM reports the time it was generated, which is not useful during snapshot testing
				`Created: .*`: "Created: redacted",

				// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
				`DocumentNamespace: https://anchore.com/.*`: "DocumentNamespace: redacted",

				// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
				`LicenseListVersion: .*`: "LicenseListVersion: redacted",
			},
		)
}
