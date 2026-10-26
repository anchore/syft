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
		TemplatePath: "testdata/legacy/csv.template",
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
		TemplatePath: "testdata/legacy/csv-hasField.template",
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
		TemplatePath: "testdata/csv.template",
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
		TemplatePath: "testdata/csv-hasField.template",
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

func TestFuncMap_ExposesDateFunctions_ExcludesEnvAndNetwork(t *testing.T) {
	enc, err := NewFormatEncoder(DefaultEncoderConfig())
	require.NoError(t, err)

	e, ok := enc.(encoder)
	require.True(t, ok)

	// date/time functions (the reason for issue #2372) should be available
	for _, name := range []string{"now", "date", "dateInZone", "dateModify", "unixEpoch"} {
		_, exists := e.funcMap[name]
		assert.Truef(t, exists, "expected date function %q to be available", name)
	}

	// functions that reach into the environment or network must remain excluded.
	// rand*/uuidv4 are also kept out to preserve hermetic (repeatable) output.
	for _, name := range []string{"env", "expandenv", "getHostByName", "randAlphaNum", "uuidv4"} {
		_, exists := e.funcMap[name]
		assert.Falsef(t, exists, "expected non-hermetic function %q to be excluded", name)
	}
}

func TestFormatWithoutOptions(t *testing.T) {
	f, err := NewFormatEncoder(DefaultEncoderConfig())
	require.NoError(t, err)
	err = f.Encode(nil, testutil.DirectoryInput(t, t.TempDir()))
	assert.ErrorContains(t, err, "no template file provided")
}
