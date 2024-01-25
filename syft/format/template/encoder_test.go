package template

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/internal/testutil"
)

var updateSnapshot = flag.Bool("update-template", false, "update the *.golden files for json encoders")

func TestFormatWithOption_Legacy(t *testing.T) {
	f, err := NewFormatEncoder(EncoderConfig{
		TemplatePath: "test-fixtures/legacy/csv.template",
		Legacy:       true,
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

func TestFormatWithOptionAndHasField_Legacy(t *testing.T) {
	f, err := NewFormatEncoder(EncoderConfig{
		TemplatePath: "test-fixtures/legacy/csv-hasField.template",
		Legacy:       true,
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

func TestFormatWithOption(t *testing.T) {
	f, err := NewFormatEncoder(EncoderConfig{
		TemplatePath: "test-fixtures/csv.template",
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
		TemplatePath: "test-fixtures/csv-hasField.template",
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
	f, err := NewFormatEncoder(DefaultEncoderConfig())
	require.NoError(t, err)
	err = f.Encode(nil, testutil.DirectoryInput(t, t.TempDir()))
	assert.ErrorContains(t, err, "no template file provided")
}
