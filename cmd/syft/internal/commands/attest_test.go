package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/clio/cliotestutils"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_attestSingleFormat(t *testing.T) {
	s := &sbom.SBOM{
		Artifacts:     sbom.Artifacts{},
		Relationships: nil,
		Source: source.Description{
			ID:      "source-id",
			Name:    "source-name",
			Version: "source-version",
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft-test",
			Version: "non-version",
		},
	}

	opts := &attestOptions{
		Output: defaultAttestOutputOptions(),
	}

	encs, err := opts.Encoders()
	require.NoError(t, err)

	encoders := format.NewEncoderCollection(encs...)
	encoder := encoders.GetByString("syft-json")
	require.NotNil(t, encoder, "expected to find encoder for syft-json")

	sbomFile := &bytes.Buffer{}
	err = encoder.Encode(sbomFile, *s)
	require.NoError(t, err)

	re := regexp.MustCompile(`(?s)"schema":\W*\{.*?},?`)
	subject := re.ReplaceAllString(sbomFile.String(), `"schema":{}`)

	wantSbomFile := `{
 "artifacts": [],
 "artifactRelationships": [],
 "source": {
  "id": "source-id",
  "name": "source-name",
  "version": "source-version",
  "type": "",
  "metadata": null
 },
 "distro": {},
 "descriptor": {
  "name": "syft-test",
  "version": "non-version"
 },
 "schema": {}
}`

	assert.JSONEq(t, wantSbomFile, subject)
}

func Test_attestCommand(t *testing.T) {
	cmdPrefix := cosignBinName
	lp, err := exec.LookPath(cosignBinName)
	if err == nil {
		cmdPrefix = lp
	}

	fullCmd := func(args string) string {
		return fmt.Sprintf("%s %s", cmdPrefix, args)
	}

	type args struct {
		sbomFilepath string
		outputName   string
		opts         attestOptions
		userInput    string
	}
	tests := []struct {
		name        string
		args        args
		wantCmd     string
		wantEnvVars map[string]string
		notEnvVars  []string
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name: "with key and password",
			args: args{
				userInput:    "myimage",
				sbomFilepath: "/tmp/sbom-filepath.json",
				outputName:   "syft-json",
				opts: func() attestOptions {
					def := defaultAttestOptions()
					def.Attest.Key = "key"
					def.Attest.Password = "password"
					return def
				}(),
			},
			wantCmd: fullCmd("attest myimage --predicate /tmp/sbom-filepath.json --type custom -y --key key"),
			wantEnvVars: map[string]string{
				"COSIGN_PASSWORD": "password",
			},
			notEnvVars: []string{
				"COSIGN_EXPERIMENTAL",
			},
		},
		{
			name: "keyless",
			args: args{
				userInput:    "myimage",
				sbomFilepath: "/tmp/sbom-filepath.json",
				outputName:   "syft-json",
				opts: func() attestOptions {
					def := defaultAttestOptions()
					return def
				}(),
			},
			wantCmd: fullCmd("attest myimage --predicate /tmp/sbom-filepath.json --type custom -y"),
			wantEnvVars: map[string]string{
				"COSIGN_EXPERIMENTAL": "1",
			},
			notEnvVars: []string{
				"COSIGN_PASSWORD",
			},
		},
		{
			name: "spdx-json format",
			args: args{
				userInput:    "myimage",
				sbomFilepath: "/tmp/sbom-filepath.json",
				outputName:   "spdx-json",
				opts: func() attestOptions {
					def := defaultAttestOptions()
					def.Attest.Key = "key"
					def.Attest.Password = "password"
					return def
				}(),
			},
			wantCmd: fullCmd("attest myimage --predicate /tmp/sbom-filepath.json --type spdxjson -y --key key"),
			wantEnvVars: map[string]string{
				"COSIGN_PASSWORD": "password",
			},
		},
		{
			name: "cyclonedx-json format",
			args: args{
				userInput:    "myimage",
				sbomFilepath: "/tmp/sbom-filepath.json",
				outputName:   "cyclonedx-json",
				opts: func() attestOptions {
					def := defaultAttestOptions()
					def.Attest.Key = "key"
					def.Attest.Password = "password"
					return def
				}(),
			},
			wantCmd: fullCmd("attest myimage --predicate /tmp/sbom-filepath.json --type cyclonedx -y --key key"),
			wantEnvVars: map[string]string{
				"COSIGN_PASSWORD": "password",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := attestCommand(tt.args.sbomFilepath, tt.args.outputName, &tt.args.opts, tt.args.userInput)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.wantCmd, got.String())

			gotEnv := strset.New(got.Env...)

			for k, v := range tt.wantEnvVars {
				assert.True(t, gotEnv.Has(fmt.Sprintf("%s=%s", k, v)))
			}

			for _, k := range tt.notEnvVars {
				for _, env := range got.Env {
					fields := strings.Split(env, "=")
					if fields[0] == k {
						t.Errorf("attestCommand() unexpected environment variable %s", k)
					}
				}
			}
		})
	}
}

func Test_predicateType(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "cyclonedx-json",
			want: "cyclonedx",
		},
		{
			name: "spdx-tag-value",
			want: "spdx",
		},
		{
			name: "spdx-tv",
			want: "spdx",
		},
		{
			name: "spdx-json",
			want: "spdxjson",
		},
		{
			name: "json",
			want: "spdxjson",
		},
		{
			name: "syft-json",
			want: "custom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, predicateType(tt.name), "predicateType(%v)", tt.name)
		})
	}
}

func Test_buildSBOMForAttestation(t *testing.T) {
	// note: this test is only meant to test that the filter function is wired
	// and not the correctness of the function in depth
	type args struct {
		id        clio.Identification
		opts      *options.Catalog
		userInput string
	}
	tests := []struct {
		name    string
		args    args
		want    *sbom.SBOM
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "do not allow directory scans",
			args: args{
				opts: func() *options.Catalog {
					def := defaultAttestOptions()
					return &def.Catalog
				}(),
				userInput: "dir:/tmp/something",
			},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			_, err := generateSBOMForAttestation(context.Background(), tt.args.id, tt.args.opts, tt.args.userInput)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
		})
	}
}

func Test_attestCLIWiring(t *testing.T) {
	id := clio.Identification{
		Name:    "syft",
		Version: "testing",
	}
	cfg := internal.AppClioSetupConfig(id, io.Discard)
	tests := []struct {
		name          string
		assertionFunc func(*testing.T, *cobra.Command, []string, ...any)
		wantOpts      attestOptions
		args          []string
		env           map[string]string
	}{
		{
			name:          "key flag is accepted",
			args:          []string{"some-image:some-tag", "--key", "some-cosign-key.key"},
			assertionFunc: hasAttestOpts(options.Attest{Key: "some-cosign-key.key"}),
		},
		{
			name: "key password is read from env",
			args: []string{"some-image:some-tag", "--key", "cosign.key"},
			env: map[string]string{
				"SYFT_ATTEST_PASSWORD": "some-password",
			},
			assertionFunc: hasAttestOpts(options.Attest{
				Key:      "cosign.key",
				Password: "some-password",
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != nil {
				for k, v := range tt.env {
					t.Setenv(k, v)
				}
			}
			app := cliotestutils.NewApplication(t, cfg, tt.assertionFunc)
			cmd := Attest(app)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.NoError(t, err)
		})
	}
}

func hasAttestOpts(wantOpts options.Attest) cliotestutils.AssertionFunc {
	return func(t *testing.T, _ *cobra.Command, _ []string, cfgs ...any) {
		assert.Equal(t, len(cfgs), 1)
		attestOpts, ok := cfgs[0].(*attestOptions)
		require.True(t, ok)
		if d := cmp.Diff(wantOpts, attestOpts.Attest); d != "" {
			t.Errorf("mismatched attest options (-want +got):\n%s", d)
		}
	}
}
