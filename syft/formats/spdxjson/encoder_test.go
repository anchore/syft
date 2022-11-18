package spdxjson

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/common/testutils"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var updateSpdxJson = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json encoders")

func TestSPDXJSONDirectoryEncoder(t *testing.T) {
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		testutils.DirectoryInput(t),
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func TestSPDXJSONImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
		testImage,
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"
	s := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	addRelationships(&s)
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		s,
		testImage,
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func addRelationships(s *sbom.SBOM) {
	catalog := s.Artifacts.PackageCatalog.Sorted()
	s.Artifacts.FileMetadata = map[source.Coordinates]source.FileMetadata{}

	for _, f := range []string{"/f1", "/f2", "/d1/f3", "/d2/f4", "/z1/f5", "/a1/f6"} {
		meta := source.FileMetadata{}
		coords := source.Coordinates{RealPath: f}
		s.Artifacts.FileMetadata[coords] = meta

		s.Relationships = append(s.Relationships, artifact.Relationship{
			From: catalog[0],
			To:   coords,
			Type: artifact.ContainsRelationship,
		})
	}
}

func spdxJsonRedactor(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`"created": .*`).ReplaceAll(s, []byte("redacted"))

	// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
	s = regexp.MustCompile(`"documentNamespace": .*`).ReplaceAll(s, []byte("redacted"))

	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	return regexp.MustCompile(`"licenseListVersion": .*`).ReplaceAll(s, []byte("redacted"))
}
