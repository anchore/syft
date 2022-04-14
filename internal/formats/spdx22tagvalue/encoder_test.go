package spdx22tagvalue

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var updateSpdxTagValue = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv encoders")

func TestSPDXTagValueDirectoryEncoder(t *testing.T) {

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		testutils.DirectoryInput(t),
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func TestSPDXTagValueImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
		testImage,
		*updateSpdxTagValue,
		spdxTagValueRedactor,
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
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		sbom.SBOM{
			Artifacts: sbom.Artifacts{
				PackageCatalog: pkg.NewCatalog(pkgs...),
			},
			Relationships: nil,
			Source: source.Metadata{
				Scheme: source.DirectoryScheme,
			},
			Descriptor: sbom.Descriptor{},
		},
		true,
		spdxTagValueRedactor,
	)
}

func spdxTagValueRedactor(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`Created: .*`).ReplaceAll(s, []byte("redacted"))

	// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
	s = regexp.MustCompile(`DocumentNamespace: https://anchore.com/syft/.*`).ReplaceAll(s, []byte("redacted"))

	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	return regexp.MustCompile(`LicenseListVersion: .*`).ReplaceAll(s, []byte("redacted"))
}
