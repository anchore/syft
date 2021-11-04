package spdx22json

import (
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/anchore/syft/syft/format"
)

var updateSpdxJson = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json presenters")

func TestSPDXJSONDirectoryPresenter(t *testing.T) {
	catalog, metadata, distro := testutils.DirectoryInput(t)
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, distro, source.UnknownScope),
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func TestSPDXJSONImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, distro := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, distro, source.SquashedScope),
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
