package cyclonedxjson

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateSnapshot = flag.Bool("update-cyclonedx-json", false, "update the *.golden files for cyclone-dx JSON encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestCycloneDxDirectoryEncoder(t *testing.T) {
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

func TestCycloneDxImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.ImageInput(t, testImage),
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

type replacement struct {
	pattern *regexp.Regexp
	replace string
}

func (r replacement) redact(b []byte) []byte {
	return r.pattern.ReplaceAll(b, []byte(r.replace))
}

func (r redactor) redact(s []byte) []byte {
	replacements := []replacement{
		// UUIDs
		{
			pattern: regexp.MustCompile(`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			replace: `urn:uuid:redacted`,
		},

		// timestamps
		{
			pattern: regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`),
			replace: `timestamp:redacted`,
		},

		// image hashes
		{
			pattern: regexp.MustCompile(`sha256:[A-Fa-f0-9]{64}`),
			replace: `sha256:redacted`,
		},

		// bom-refs
		{
			pattern: regexp.MustCompile(`"bom-ref":\s*"[^"]+"`),
			replace: `"bom-ref":"redacted"`,
		},
	}

	for _, r := range replacements {
		s = r.redact(s)
	}

	if r.dir != "" {
		s = bytes.ReplaceAll(s, []byte(r.dir), []byte("redacted"))
	}
	return s
}
