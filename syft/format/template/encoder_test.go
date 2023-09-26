package template

import (
	"flag"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/format/internal/testutil"
)

var updateSnapshot = flag.Bool("update-template", false, "update the *.golden files for json encoders")

func TestFormatWithOption(t *testing.T) {
	f, err := NewFormatEncoder(EncoderConfig{
		TemplatePath:      "test-fixtures/csv.template",
		JSONEncoderConfig: syftjson.DefaultEncoderConfig(),
	})
	require.NoError(t, err)

	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInput(t, t.TempDir()),
			Format:                      f,
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)
}

func TestFormatWithOptionAndHasField(t *testing.T) {
	f, err := NewFormatEncoder(EncoderConfig{
		TemplatePath:      "test-fixtures/csv-hasField.template",
		JSONEncoderConfig: syftjson.DefaultEncoderConfig(),
	})
	require.NoError(t, err)

	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInputWithAuthorField(t),
			Format:                      f,
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)

}

func TestFormatWithoutOptions(t *testing.T) {
	f := DefaultFormatEncoder()
	err := f.Encode(nil, testutil.DirectoryInput(t, t.TempDir()))
	assert.ErrorContains(t, err, "no template file provided")
}
