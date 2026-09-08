package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func convertTestSBOM() sbom.SBOM {
	catalog := pkg.NewCollection()
	catalog.Add(pkg.Package{
		Name:    "musl-utils",
		Version: "1.2.3-r4",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Locations: file.NewLocationSet(
			file.NewLocation("/lib/apk/db/installed"),
		),
		PURL: "pkg:apk/alpine/musl-utils@1.2.3-r4",
	})

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
		Source: source.Description{
			ID:      "some-id",
			Name:    "some-dir",
			Version: "latest",
			Metadata: source.DirectoryMetadata{
				Path: "/some/path",
			},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.0.0-test",
		},
	}
}

func mustConvertEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}

func encodeConvertTestSBOM(t *testing.T, enc sbom.FormatEncoder) []byte {
	buf := &bytes.Buffer{}
	require.NoError(t, enc.Encode(buf, convertTestSBOM()))
	return buf.Bytes()
}

// prettySyftJSON returns the test SBOM as pretty-printed syft-json. Pretty input makes a verbatim copy
// distinguishable from a re-encode, since re-encoding always produces compact output here.
func prettySyftJSON(t *testing.T) []byte {
	cfg := syftjson.DefaultEncoderConfig()
	cfg.Pretty = true
	return encodeConvertTestSBOM(t, mustConvertEncoder(syftjson.NewFormatEncoderWithConfig(cfg)))
}

func Test_partitionOutputsBySourceFormat(t *testing.T) {
	syftEncoder := mustConvertEncoder(syftjson.NewFormatEncoderWithConfig(syftjson.DefaultEncoderConfig()))
	syftVersion := syftEncoder.Version()
	syftContent := encodeConvertTestSBOM(t, syftEncoder)

	// the same document claiming an older schema version
	olderSyftContent := bytes.ReplaceAll(syftContent, []byte(`"version":"`+syftVersion+`"`), []byte(`"version":"16.0.0"`))
	require.NotEqual(t, syftContent, olderSyftContent)

	cdxContent := encodeConvertTestSBOM(t, mustConvertEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())))

	tests := []struct {
		name          string
		content       []byte
		outputs       []string
		wantUnchanged []string
		wantToConvert []string
	}{
		{
			name:          "syft-json matches the bare format name",
			content:       syftContent,
			outputs:       []string{"syft-json"},
			wantUnchanged: []string{"syft-json"},
		},
		{
			name:          "syft-json matches its alias",
			content:       syftContent,
			outputs:       []string{"json"},
			wantUnchanged: []string{"json"},
		},
		{
			name:          "syft-json matches an explicit version and file path",
			content:       syftContent,
			outputs:       []string{"syft-json@" + syftVersion + "=out/some.syft.json"},
			wantUnchanged: []string{"syft-json@" + syftVersion + "=out/some.syft.json"},
		},
		{
			name:          "syft-json at an older schema version requires conversion",
			content:       olderSyftContent,
			outputs:       []string{"syft-json"},
			wantToConvert: []string{"syft-json"},
		},
		{
			name:          "a different output format requires conversion",
			content:       syftContent,
			outputs:       []string{"spdx-json"},
			wantToConvert: []string{"spdx-json"},
		},
		{
			name:          "mixed outputs are partitioned",
			content:       syftContent,
			outputs:       []string{"syft-json=a.json", "spdx-json=b.json", "cyclonedx-xml"},
			wantUnchanged: []string{"syft-json=a.json"},
			wantToConvert: []string{"spdx-json=b.json", "cyclonedx-xml"},
		},
		{
			name:          "unknown format is left for the writer to report",
			content:       syftContent,
			outputs:       []string{"bogus"},
			wantToConvert: []string{"bogus"},
		},
		{
			name:          "non syft-json input is always converted, even when it matches the output",
			content:       cdxContent,
			outputs:       []string{"cyclonedx-json"},
			wantToConvert: []string{"cyclonedx-json"},
		},
		{
			name:          "unidentifiable content is left for the decoder to report",
			content:       []byte("definitely not an sbom"),
			outputs:       []string{"syft-json"},
			wantToConvert: []string{"syft-json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := options.DefaultOutput()
			output.Outputs = tt.outputs

			unchanged, toConvert, err := partitionOutputsBySourceFormat(output, tt.content)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnchanged, unchanged)
			assert.Equal(t, tt.wantToConvert, toConvert)
		})
	}
}

func Test_RunConvert_passthroughExactFormat(t *testing.T) {
	syftContent := prettySyftJSON(t)

	newOpts := func(passthrough bool, outputs ...string) *ConvertOptions {
		opts := &ConvertOptions{
			Output: options.DefaultOutput(),
			Convert: options.Convert{
				PassthroughExactFormat: passthrough,
			},
		}
		opts.Outputs = outputs
		return opts
	}

	writeInput := func(t *testing.T, content []byte) string {
		input := filepath.Join(t.TempDir(), "input.json")
		require.NoError(t, os.WriteFile(input, content, 0600))
		return input
	}

	t.Run("matching output is copied unchanged while others are converted", func(t *testing.T) {
		dir := t.TempDir()
		syftOut := filepath.Join(dir, "out.syft.json")
		spdxOut := filepath.Join(dir, "out.spdx.json")

		opts := newOpts(true, "syft-json="+syftOut, "spdx-json="+spdxOut)
		require.NoError(t, RunConvert(opts, writeInput(t, syftContent)))

		got, err := os.ReadFile(syftOut)
		require.NoError(t, err)
		assert.Equal(t, syftContent, got)

		spdx, err := os.ReadFile(spdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(spdx))
		assert.Equal(t, spdxjson.ID, id)
	})

	t.Run("STDIN input is copied unchanged while others are converted", func(t *testing.T) {
		dir := t.TempDir()
		syftOut := filepath.Join(dir, "out.syft.json")
		spdxOut := filepath.Join(dir, "out.spdx.json")

		stdin, err := os.Open(writeInput(t, syftContent))
		require.NoError(t, err)
		defer stdin.Close()

		originalStdin := os.Stdin
		os.Stdin = stdin
		t.Cleanup(func() { os.Stdin = originalStdin })

		opts := newOpts(true, "syft-json="+syftOut, "spdx-json="+spdxOut)
		require.NoError(t, RunConvert(opts, "-"))

		got, err := os.ReadFile(syftOut)
		require.NoError(t, err)
		assert.Equal(t, syftContent, got)

		spdx, err := os.ReadFile(spdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(spdx))
		assert.Equal(t, spdxjson.ID, id)
	})

	t.Run("piped STDIN input is copied unchanged while others are converted", func(t *testing.T) {
		dir := t.TempDir()
		syftOut := filepath.Join(dir, "out.syft.json")
		spdxOut := filepath.Join(dir, "out.spdx.json")

		pipeReader, pipeWriter, err := os.Pipe()
		require.NoError(t, err)
		defer pipeReader.Close()
		go func() {
			defer pipeWriter.Close()
			_, _ = pipeWriter.Write(syftContent)
		}()

		originalStdin := os.Stdin
		os.Stdin = pipeReader
		t.Cleanup(func() { os.Stdin = originalStdin })

		opts := newOpts(true, "syft-json="+syftOut, "spdx-json="+spdxOut)
		require.NoError(t, RunConvert(opts, "-"))

		got, err := os.ReadFile(syftOut)
		require.NoError(t, err)
		assert.Equal(t, syftContent, got)

		spdx, err := os.ReadFile(spdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(spdx))
		assert.Equal(t, spdxjson.ID, id)
	})

	t.Run("without the option the matching output is re-encoded", func(t *testing.T) {
		syftOut := filepath.Join(t.TempDir(), "out.syft.json")

		opts := newOpts(false, "syft-json="+syftOut)
		require.NoError(t, RunConvert(opts, writeInput(t, syftContent)))

		got, err := os.ReadFile(syftOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(got))
		assert.Equal(t, syftjson.ID, id)
		// the input was pretty-printed and the encoder is not configured to be, so a re-encode cannot reproduce it
		assert.NotEqual(t, syftContent, got)
	})

	t.Run("non syft-json input is re-encoded even when it matches the output", func(t *testing.T) {
		cdxContent := encodeConvertTestSBOM(t, mustConvertEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())))
		cdxOut := filepath.Join(t.TempDir(), "out.cdx.json")

		opts := newOpts(true, "cyclonedx-json="+cdxOut)
		require.NoError(t, RunConvert(opts, writeInput(t, cdxContent)))

		got, err := os.ReadFile(cdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(got))
		assert.Equal(t, cyclonedxjson.ID, id)
		// a fresh serial number is minted on every encode, so a round trip never reproduces the input
		assert.NotEqual(t, cdxContent, got)
	})

	t.Run("the deprecated --file path is honored", func(t *testing.T) {
		syftOut := filepath.Join(t.TempDir(), "out.syft.json")

		opts := newOpts(true, "syft-json")
		opts.LegacyFile = syftOut
		require.NoError(t, RunConvert(opts, writeInput(t, syftContent)))

		got, err := os.ReadFile(syftOut)
		require.NoError(t, err)
		assert.Equal(t, syftContent, got)
	})

	t.Run("writing over the input file leaves it intact", func(t *testing.T) {
		input := writeInput(t, syftContent)

		opts := newOpts(true, "syft-json="+input)
		require.NoError(t, RunConvert(opts, input))

		got, err := os.ReadFile(input)
		require.NoError(t, err)
		assert.Equal(t, syftContent, got)
	})

	t.Run("an invalid output fails before anything is written", func(t *testing.T) {
		syftOut := filepath.Join(t.TempDir(), "out.syft.json")

		opts := newOpts(true, "syft-json="+syftOut, "bogus")
		require.Error(t, RunConvert(opts, writeInput(t, syftContent)))

		assert.NoFileExists(t, syftOut)
	})

	t.Run("a missing input file is reported", func(t *testing.T) {
		syftOut := filepath.Join(t.TempDir(), "out.syft.json")

		opts := newOpts(true, "syft-json="+syftOut)
		err := RunConvert(opts, filepath.Join(t.TempDir(), "does-not-exist.json"))
		require.ErrorContains(t, err, "failed to open SBOM file")

		assert.NoFileExists(t, syftOut)
	})

	t.Run("unrecognized input is left to the decoder to reject", func(t *testing.T) {
		syftOut := filepath.Join(t.TempDir(), "out.syft.json")

		opts := newOpts(true, "syft-json="+syftOut)
		err := RunConvert(opts, writeInput(t, []byte("definitely not an sbom")))
		require.ErrorContains(t, err, "failed to decode SBOM")
	})
}
