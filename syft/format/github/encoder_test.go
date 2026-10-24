package github

import (
	"flag"
	"runtime"
	"testing"

	"github.com/anchore/syft/syft/format/internal/testutil"
)

var updateSnapshot = flag.Bool("update-github", false, "update the *.golden files for github encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestGithubDirectoryEncoder(t *testing.T) {
	if runtime.GOOS == "windows" {
		// the golden snapshot embeds the posix source path (and the source ID derived from it)
		t.Skip("directory snapshot is posix path specific")
	}
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
