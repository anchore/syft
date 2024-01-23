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
		{from: "syft-json", to: "cyclonedx-json", expect: mustEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "cyclonedx-xml", expect: mustEncoder(cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.DefaultEncoderConfig()))},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("from %s to %s", test.from, test.to), func(t *testing.T) {
			sbomArgs := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", test.from}
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

func mustEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}
