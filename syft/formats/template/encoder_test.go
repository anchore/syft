package template

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/formats/internal/testutils"
)

var updateSnapshot = flag.Bool("update-template", false, "update the *.golden files for json encoders")

func TestFormatWithOption(t *testing.T) {
	f := OutputFormat{}
	f.SetTemplatePath("test-fixtures/csv.template")

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInput(t, t.TempDir()),
			Format:                      f,
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)
}

func TestFormatWithOptionAndHasField(t *testing.T) {
	f := OutputFormat{}
	f.SetTemplatePath("test-fixtures/csv-hasField.template")

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInputWithAuthorField(t),
			Format:                      f,
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)

}

func TestFormatWithoutOptions(t *testing.T) {
	f := Format()
	err := f.Encode(nil, testutils.DirectoryInput(t, t.TempDir()))
	assert.ErrorContains(t, err, "no template file: please provide a template path")
}
