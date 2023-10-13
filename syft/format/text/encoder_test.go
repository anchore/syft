package text

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/format/internal/testutil"
)

var updateSnapshot = flag.Bool("update-text", false, "update the *.golden files for text encoder")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestTextDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInput(t, dir),
			Format:                      NewFormatEncoder(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(dir),
		},
	)
}

func TestTextImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.ImageInput(t, testImage, testutil.FromSnapshot()),
			Format:                      NewFormatEncoder(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactor:                    redactor(),
		},
	)
}

func redactor(values ...string) testutil.Redactor {
	return testutil.NewRedactions().
		WithValuesRedacted(values...)
}
