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
			sbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope, false)
			format := syft.FormatByID(syftjson.ID)

			f, err := ioutil.TempFile("", "test-convert-sbom-")
			require.NoError(t, err)
			defer func() {
				os.Remove(f.Name())
			}()

			err = format.Encode(f, sbom)
			require.NoError(t, err)

			ctx := context.Background()
			app := &config.Application{Outputs: []string{format.ID().String()}}

			// stdout reduction of test noise
			rescue := os.Stdout // keep backup of the real stdout
			os.Stdout, _ = os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
			defer func() {
				os.Stdout = rescue
			}()

			err = convert.Run(ctx, app, []string{f.Name()})
			require.NoError(t, err)
			file, err := ioutil.ReadFile(f.Name())
			require.NoError(t, err)

			formatFound := syft.IdentifyFormat(file)
			if format.ID() == table.ID {
				require.Nil(t, formatFound)
				return
			}
			require.Equal(t, format.ID(), formatFound.ID())
		})
	}
}
