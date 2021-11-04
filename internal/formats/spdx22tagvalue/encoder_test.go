package spdx22tagvalue

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/anchore/syft/syft/format"
)

var updateSpdxTagValue = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv presenters")

func TestSPDXTagValueDirectoryPresenter(t *testing.T) {
	catalog, metadata, d := testutils.DirectoryInput(t)
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, d, source.UnknownScope),
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func TestSPDXTagValueImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, d := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, d, source.SquashedScope),
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
