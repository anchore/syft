package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/cli/commands"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func mustEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}

// TestConvertCmd tests if the converted SBOM is a valid document according
// to spec.
// TODO: This test can, but currently does not, check the converted SBOM content. It
// might be useful to do that in the future, once we gather a better understanding of
// what users expect from the convert command.
func TestConvertCmd(t *testing.T) {
	tests := []struct {
		name   string
		format sbom.FormatEncoder
	}{
		{
			name:   "syft-json",
			format: syftjson.NewFormatEncoder(),
		},
		{
			name:   "spdx-json",
			format: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())),
		},
		{
			name:   "spdx-tag-value",
			format: mustEncoder(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig())),
		},
		{
			name:   "cyclonedx-json",
			format: mustEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())),
		},
		{
			name:   "cyclonedx-xml",
			format: mustEncoder(cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.DefaultEncoderConfig())),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			syftSbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope, nil)
			syftFormat := syftjson.NewFormatEncoder()

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
				Output: options.Output{
					Outputs: []string{fmt.Sprintf("%s=%s", test.format.ID().String(), formatFile.Name())},
				},
			}
			require.NoError(t, opts.PostLoad())

			// stdout reduction of test noise
			rescue := os.Stdout // keep backup of the real stdout
			os.Stdout, _ = os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
			defer func() {
				os.Stdout = rescue
			}()

			err = commands.RunConvert(opts, syftFile.Name())
			require.NoError(t, err)

			foundID, _ := format.Identify(formatFile)
			require.Equal(t, test.format.ID(), foundID)
		})
	}
}
