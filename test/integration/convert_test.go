package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/syft/cmd/syft/cli/convert"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"
)

// TestConvertCmd tests if the converted SBOM is a valid document according
// to spec.
// FIXME: This test can, but currently does not, check the converted SBOM content. It
// might be useful to do that in the future, once we gather a better understanding of
// what users spect from the convert command.
func TestConvertCmd(t *testing.T) {
	for _, formatID := range convert.ConvertableFormats {
		t.Run(formatID.String(), func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope)
			format := syft.FormatByID(syftjson.ID)

			f, err := ioutil.TempFile("", "test-convert-sbom-")
			require.NoError(t, err)
			defer func() {
				err := f.Close()
				require.NoError(t, err)
				os.Remove(f.Name())
			}()

			err = format.Encode(f, sbom)
			require.NoError(t, err)

			stdr, stdw, err := os.Pipe()
			require.NoError(t, err)
			originalStdout := os.Stdout
			os.Stdout = stdw

			ctx := context.Background()
			app := &config.Application{Outputs: []string{formatID.String()}}

			err = convert.Run(ctx, app, []string{f.Name()})
			require.NoError(t, err)
			stdw.Close()

			out, err := ioutil.ReadAll(stdr)
			require.NoError(t, err)

			os.Stdout = originalStdout
			// t.Logf("out: %s", out)

			formatFound := syft.IdentifyFormat(out)
			if formatID == table.ID {
				require.Nil(t, formatFound)
				return
			}
			require.Equal(t, formatID, formatFound.ID())
			// t.Logf("ff: %s", ff)
		})
	}
}
