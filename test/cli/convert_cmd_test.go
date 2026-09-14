package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

func TestConvertCmd(t *testing.T) {
	assertions := []traitAssertion{
		assertInOutput("musl-utils"),
		assertSuccessfulReturnCode,
	}

	tests := []struct {
		from   string
		to     string
		expect sbom.FormatEncoder
	}{
		{from: "syft-json", to: "spdx-tag-value", expect: mustEncoder(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig()))},
		{from: "syft-json", to: "spdx-json", expect: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "spdx-json@3.0", expect: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "cyclonedx-json", expect: mustEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "cyclonedx-xml", expect: mustEncoder(cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.DefaultEncoderConfig()))},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("from %s to %s", test.from, test.to), func(t *testing.T) {
			sbomArgs := []string{"dir:./testdata/image-pkg-coverage", "-o", test.from}
			cmd, stdout, stderr := runSyft(t, nil, sbomArgs...)
			if cmd.ProcessState.ExitCode() != 0 {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
				t.Fatalf("failure executing syft creating an sbom")
				return
			}

			convertArgs := []string{"convert", "-", "-o", test.to}
			cmd = getSyftCommand(t, convertArgs...)

			cmd.Stdin = strings.NewReader(stdout)
			stdout, stderr = runCommandObj(t, cmd, nil, false)

			for _, traitFn := range assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)

			// let's make sure the output is valid relative to the expected format
			foundID, _ := format.Identify(strings.NewReader(stdout))
			require.Equal(t, test.expect.ID(), foundID)

		})
	}
}

func TestConvertCmd_PassthroughExactFormat(t *testing.T) {
	// pretty-printed input makes a verbatim copy distinguishable from a re-encode (which is compact)
	sbomArgs := []string{"dir:./testdata/image-pkg-coverage", "-o", "syft-json"}
	cmd, input, stderr := runSyft(t, map[string]string{"SYFT_FORMAT_PRETTY": "true"}, sbomArgs...)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT:\n", input)
		t.Log("STDERR:\n", stderr)
		t.Log("COMMAND:", strings.Join(cmd.Args, " "))
		t.Fatalf("failure executing syft creating an sbom")
		return
	}

	inputID, inputVersion := format.Identify(strings.NewReader(input))
	require.Equal(t, syftjson.ID, inputID)
	require.NotEmpty(t, inputVersion)

	const (
		enabledWarning = "convert.passthrough-exact-format is enabled"
		copiedWarning  = "copying it unchanged instead of converting it"
	)

	tests := []struct {
		name          string
		env           map[string]string
		to            string
		wantUnchanged bool
		wantID        sbom.FormatID
		wantVersion   string
		wantInStderr  []string
		wantNotStderr []string
	}{
		{
			name:          "matching syft-json is passed through unchanged",
			env:           map[string]string{"SYFT_CONVERT_PASSTHROUGH_EXACT_FORMAT": "true"},
			to:            "syft-json",
			wantUnchanged: true,
			wantID:        syftjson.ID,
			wantVersion:   inputVersion,
			wantInStderr:  []string{enabledWarning, copiedWarning},
		},
		{
			name:          "different format is converted",
			env:           map[string]string{"SYFT_CONVERT_PASSTHROUGH_EXACT_FORMAT": "true"},
			to:            "cyclonedx-json",
			wantID:        cyclonedxjson.ID,
			wantVersion:   mustEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())).Version(),
			wantInStderr:  []string{enabledWarning},
			wantNotStderr: []string{copiedWarning},
		},
		{
			name:          "option off by default, matching syft-json is re-encoded",
			to:            "syft-json",
			wantID:        syftjson.ID,
			wantVersion:   inputVersion,
			wantNotStderr: []string{enabledWarning, copiedWarning},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := getSyftCommand(t, "convert", "-", "-o", test.to)
			cmd.Stdin = strings.NewReader(input)
			stdout, stderr := runCommandObj(t, cmd, test.env, false)

			assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
			logOutputOnFailure(t, cmd, stdout, stderr)

			foundID, foundVersion := format.Identify(strings.NewReader(stdout))
			require.Equal(t, test.wantID, foundID)
			require.Equal(t, test.wantVersion, foundVersion)

			if test.wantUnchanged {
				require.Equal(t, strings.TrimSpace(input), strings.TrimSpace(stdout))
			} else {
				require.NotEqual(t, strings.TrimSpace(input), strings.TrimSpace(stdout))
			}

			for _, want := range test.wantInStderr {
				require.Contains(t, stderr, want)
			}
			for _, notWant := range test.wantNotStderr {
				require.NotContains(t, stderr, notWant)
			}
		})
	}
}

func mustEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}
