package spdxjson

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateSnapshot = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestSPDXJSONDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInput(t, dir),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactors: []testutils.Redactor{
				redactor{dir: dir}.redact,
			},
		},
	)
}

func TestSPDXJSONImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactors: []testutils.Redactor{
				redactor{}.redact,
			},
		},
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"

	s := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AddSampleFileRelationships(&s)

	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactors: []testutils.Redactor{
				redactor{}.redact,
			},
		},
	)
}

type redactor struct {
	dir string
}

func (r redactor) redact(s []byte) []byte {
	// each SBOM reports the time it was generated, which is not useful during snapshot testing
	s = regexp.MustCompile(`"created":\s+"[^"]*"`).ReplaceAll(s, []byte(`"created":"redacted"`))

	// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
	s = regexp.MustCompile(`"documentNamespace":\s+"[^"]*"`).ReplaceAll(s, []byte(`"documentNamespace":"redacted"`))

	// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
	s = regexp.MustCompile(`"licenseListVersion":\s+"[^"]*"`).ReplaceAll(s, []byte(`"licenseListVersion":"redacted"`))

	if r.dir != "" {
		s = bytes.ReplaceAll(s, []byte(r.dir), []byte("redacted"))
	}

	return s
}
