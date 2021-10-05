package packages

import (
	"flag"
	"regexp"
	"testing"
)

var updateSpdxJson = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json presenters")

func TestSPDXJSONDirectoryPresenter(t *testing.T) {
	catalog, metadata, _ := presenterDirectoryInput(t)
	assertPresenterAgainstGoldenSnapshot(t,
		NewSPDXJSONPresenter(catalog, metadata),
		*updateSpdxJson,
		spdxJsonRedactor,
	)
}

func TestSPDXJSONImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, _ := presenterImageInput(t, testImage)
	assertPresenterAgainstGoldenImageSnapshot(t,
		NewSPDXJSONPresenter(catalog, metadata),
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
