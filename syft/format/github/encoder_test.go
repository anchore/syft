package github

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/format/internal/testutil"
)

var updateSnapshot = flag.Bool("update-github", false, "update the *.golden files for github encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestGithubDirectoryEncoder(t *testing.T) {
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

func TestGithubImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.ImageInput(t, testImage),
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
		WithValuesRedacted(values...).
		WithPatternRedactors(
			map[string]string{
				// dates
				`"scanned":\s*"[^"]+"`: `"scanned":"redacted"`,

				// image metadata
				`"syft:filesystem":\s*"[^"]+"`: `"syft:filesystem":"redacted"`,
			},
		)
}
