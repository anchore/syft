package spdx22tagvalue

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateSpdxTagValue = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv presenters")

func TestSPDXTagValueDirectoryPresenter(t *testing.T) {

	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		Format().Presenter(testutils.DirectoryInput(t)),
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func TestSPDXTagValueImagePresenter(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		Format().Presenter(testutils.ImageInput(t, testImage, testutils.FromSnapshot())),
		testImage,
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func spdxTagValueRedactor(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`Created: .*`).ReplaceAll(s, []byte("redacted"))
	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	return regexp.MustCompile(`LicenseListVersion: .*`).ReplaceAll(s, []byte("redacted"))
}
