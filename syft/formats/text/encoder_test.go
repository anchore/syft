package text

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateSnapshot = flag.Bool("update-text", false, "update the *.golden files for text encoder")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestTextDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInput(t, dir),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactors: []testutils.Redactor{
				redactor{dir: dir}.redact,
			},
		},
	)
}

func TestTextImageEncoder(t *testing.T) {
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
			IsJSON:                      false,
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

	if r.dir != "" {
		s = bytes.ReplaceAll(s, []byte(r.dir), []byte("redacted"))
	}

	return s
}
