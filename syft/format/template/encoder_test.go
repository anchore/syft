package template

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var updateSnapshot = flag.Bool("update-template", false, "update the *.golden files for json encoders")

func TestFormatWithParseCPE(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, test := range []struct {
			name    string
			version string
			invalid bool
		}{
			{name: "fields", version: "1.2.3"},
			{name: "escaped colon", version: "1:3.2"},
			{name: "invalid CPE", version: "1.2.3", invalid: true},
		} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, test.name), func(t *testing.T) {
				contents := `{{range .artifacts}}{{range .cpes}}{{with parseCPE .cpe}}{{.Vendor}}|{{.Product}}|{{.Version}}{{end}}{{end}}{{end}}`
				if legacy {
					contents = `{{range .Artifacts}}{{range .CPEs}}{{with parseCPE .Value}}{{.Vendor}}|{{.Product}}|{{.Version}}{{end}}{{end}}{{end}}`
				}
				if test.invalid {
					contents = `{{parseCPE "not-a-cpe"}}`
				}
				path := filepath.Join(t.TempDir(), "cpe.template")
				require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
				enc, err := NewFormatEncoder(EncoderConfig{TemplatePath: path, Legacy: legacy})
				require.NoError(t, err)
				s := sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(pkg.Package{
					Name: "demo", Version: "1.2.3", Type: pkg.JavaPkg,
					CPEs: []cpe.CPE{{
						Attributes: cpe.Attributes{Part: "a", Vendor: "example", Product: "demo", Version: test.version},
						Source:     cpe.GeneratedSource,
					}},
				})}}
				var output bytes.Buffer
				err = enc.Encode(&output, s)
				if test.invalid {
					require.ErrorContains(t, err, "error calling parseCPE")
					return
				}
				require.NoError(t, err)
				assert.Equal(t, "example|demo|"+test.version, output.String())
			})
		}
	}
}

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
