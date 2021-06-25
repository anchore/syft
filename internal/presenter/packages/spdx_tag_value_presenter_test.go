package packages

import (
	"flag"
	"regexp"
	"testing"
)

var updateSpdxTagValue = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv presenters")

func TestSPDXTagValueDirectoryPresenter(t *testing.T) {
	catalog, metadata, _ := presenterDirectoryInput(t)
	assertPresenterAgainstGoldenSnapshot(t,
		NewSPDXTagValuePresenter(catalog, metadata),
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func TestSPDXTagValueImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, _ := presenterImageInput(t, testImage)
	assertPresenterAgainstGoldenImageSnapshot(t,
		NewSPDXTagValuePresenter(catalog, metadata),
		testImage,
		*updateSpdxTagValue,
		spdxTagValueRedactor,
	)
}

func spdxTagValueRedactor(s []byte) []byte {
	return regexp.MustCompile(`Created: .*`).ReplaceAll(s, []byte("redacted"))
}
