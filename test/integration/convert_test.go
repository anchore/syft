package integration

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/syft/cmd/syft/cli/convert"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"
)

var convertibleFormats = []sbom.Format{
	syftjson.Format(),
	spdx22json.Format(),
	spdx22tagvalue.Format(),
	cyclonedxjson.Format(),
	cyclonedxxml.Format(),
}

// TestConvertCmd tests if the converted SBOM is a valid document according
// to spec.
// TODO: This test can, but currently does not, check the converted SBOM content. It
// might be useful to do that in the future, once we gather a better understanding of
// what users expect from the convert command.
func TestConvertCmd(t *testing.T) {
	for _, format := range convertibleFormats {
		t.Run(format.ID().String(), func(t *testing.T) {
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
			app := &config.Application{Outputs: []string{format.ID().String()}}

			err = convert.Run(ctx, app, []string{f.Name()})
			require.NoError(t, err)
			stdw.Close()

			out, err := ioutil.ReadAll(stdr)
			require.NoError(t, err)

			os.Stdout = originalStdout

			formatFound := syft.IdentifyFormat(out)
			if format.ID() == table.ID {
				require.Nil(t, formatFound)
				return
			}
			require.Equal(t, format.ID(), formatFound.ID())
		})
	}
}
