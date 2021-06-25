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
	return regexp.MustCompile(`"created": .*`).ReplaceAll(s, []byte("redacted"))
}
