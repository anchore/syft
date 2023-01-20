package spdxjson

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/formats/common/testutils"
)

var updateSpdxJson = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json encoders")

func TestSPDXJSONDirectoryEncoder(t *testing.T) {
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		testutils.DirectoryInput(t),
		*updateSpdxJson,
		true,
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
		true,
		spdxJsonRedactor,
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"
	s := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AddSampleFileRelationships(&s)
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		s,
		testImage,
		*updateSpdxJson,
		true,
		spdxJsonRedactor,
	)
}

func spdxJsonRedactor(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`"created":\s+"[^"]*"`).ReplaceAll(s, []byte(`"created":""`))

	// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
	s = regexp.MustCompile(`"documentNamespace":\s+"[^"]*"`).ReplaceAll(s, []byte(`"documentNamespace":""`))

	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	return regexp.MustCompile(`"licenseListVersion":\s+"[^"]*"`).ReplaceAll(s, []byte(`"licenseListVersion":""`))
}
