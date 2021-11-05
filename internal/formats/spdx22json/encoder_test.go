package spdx22json

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateSpdxJson = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json presenters")

func TestSPDXJSONDirectoryPresenter(t *testing.T) {
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		Format().Presenter(testutils.DirectoryInput(t)),
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func TestSPDXJSONImagePresenter(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		Format().Presenter(testutils.ImageInput(t, testImage, testutils.FromSnapshot())),
		testImage,
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func spdxJsonRedactor(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`"created": .*`).ReplaceAll(s, []byte("redacted"))

	// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
	s = regexp.MustCompile(`"documentNamespace": .*`).ReplaceAll(s, []byte("redacted"))

	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	return regexp.MustCompile(`"licenseListVersion": .*`).ReplaceAll(s, []byte("redacted"))
}
