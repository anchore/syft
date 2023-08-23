package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/cli/commands"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/spdxtagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// TestConvertCmd tests if the converted SBOM is a valid document according
// to spec.
// TODO: This test can, but currently does not, check the converted SBOM content. It
// might be useful to do that in the future, once we gather a better understanding of
// what users expect from the convert command.
func TestConvertCmd(t *testing.T) {
	tests := []struct {
		name   string
		format sbom.Format
	}{
		{
			name:   "syft-json",
			format: syftjson.Format(),
		},
		{
			name:   "spdx-json",
			format: spdxjson.Format(),
		},
		{
			name:   "spdx-tag-value",
			format: spdxtagvalue.Format(),
		},
		{
			name:   "cyclonedx-json",
			format: cyclonedxjson.Format(),
		},
		{
			name:   "cyclonedx-xml",
			format: cyclonedxxml.Format(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			syftSbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope, nil)
			syftFormat := syftjson.Format()

			syftFile, err := os.CreateTemp("", "test-convert-sbom-")
			require.NoError(t, err)
			defer func() {
				_ = os.Remove(syftFile.Name())
			}()

			err = syftFormat.Encode(syftFile, syftSbom)
			require.NoError(t, err)

			formatFile, err := os.CreateTemp("", "test-convert-sbom-")
			require.NoError(t, err)
			defer func() {
				_ = os.Remove(syftFile.Name())
			}()

			opts := &commands.ConvertOptions{
				MultiOutput: options.MultiOutput{
					Outputs: []string{fmt.Sprintf("%s=%s", test.format.ID().String(), formatFile.Name())},
				},
			}

			// stdout reduction of test noise
			rescue := os.Stdout // keep backup of the real stdout
			os.Stdout, _ = os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
			defer func() {
				os.Stdout = rescue
			}()

			err = commands.RunConvert(opts, syftFile.Name())
			require.NoError(t, err)
			contents, err := os.ReadFile(formatFile.Name())
			require.NoError(t, err)

			formatFound := formats.Identify(contents)
			if test.format.ID() == table.ID {
				require.Nil(t, formatFound)
				return
			}
			require.Equal(t, test.format.ID(), formatFound.ID())
		})
	}
}
