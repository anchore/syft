package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] alpine:latest            defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry
`
	attestSchemeHelp = "\n  " + schemeHelpHeader + "\n" + imageSchemeHelp
	attestHelp       = attestExample + attestSchemeHelp
	cosignBinName    = "cosign"
)

type attestOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
	Attest              options.Attest `yaml:"attest" mapstructure:"attest"`
	Cache               options.Cache  `json:"-" yaml:"cache" mapstructure:"cache"`
}

func Attest(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := defaultAttestOptions()

	// template format explicitly not allowed
	opts.Format.Template.Enabled = false

	return app.SetupCommand(&cobra.Command{
		Use:   "attest --output [FORMAT] <IMAGE>",
		Short: "Generate an SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation that will be uploaded to the image registry",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
			"appName": id.Name,
			"command": "attest",
		}),
		Args:    validateScanArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runAttest(cmd.Context(), id, &opts, args[0])
		},
	}, &opts)
}

func defaultAttestOptions() attestOptions {
	return attestOptions{
		Output:      defaultAttestOutputOptions(),
		UpdateCheck: options.DefaultUpdateCheck(),
		Catalog:     options.DefaultCatalog(),
		Cache:       options.DefaultCache(),
	}
}

func defaultAttestOutputOptions() options.Output {
	return options.Output{
		AllowMultipleOutputs: false,
		AllowToFile:          false,
		AllowableOptions: []string{
			string(syftjson.ID),
			string(cyclonedxjson.ID),
			string(spdxjson.ID),
			string(spdxtagvalue.ID),
		},
		Outputs: []string{syftjson.ID.String()},
		OutputFile: options.OutputFile{ //nolint:staticcheck
			Enabled: false, // explicitly not allowed
		},
		Format: options.DefaultFormat(),
	}
}

func runAttest(ctx context.Context, id clio.Identification, opts *attestOptions, userInput string) error {
	// TODO: what other validation here besides binary name?
	if !commandExists(cosignBinName) {
		return fmt.Errorf("'syft attest' requires cosign to be installed, however it does not appear to be on PATH")
	}

	// this is the file that will contain the SBOM being attested
	f, err := os.CreateTemp("", "syft-attest-")
	if err != nil {
		return fmt.Errorf("unable to create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	s, err := generateSBOMForAttestation(ctx, id, &opts.Catalog, userInput)
	if err != nil {
		return fmt.Errorf("unable to build SBOM: %w", err)
	}

	if err = writeSBOMToFormattedFile(s, f, opts); err != nil {
		return fmt.Errorf("unable to write SBOM to file: %w", err)
	}

	if err = createAttestation(f.Name(), opts, userInput); err != nil {
		return err
	}

	bus.Notify("Attestation has been created, please check your registry for the output or use the cosign command:")
	bus.Notify(fmt.Sprintf("cosign download attestation %s", userInput))
	return nil
}

func writeSBOMToFormattedFile(s *sbom.SBOM, sbomFile io.Writer, opts *attestOptions) error {
	if sbomFile == nil {
		return fmt.Errorf("no output file provided")
	}

	encs, err := opts.Format.Encoders()
	if err != nil {
		return fmt.Errorf("unable to create encoders: %w", err)
	}

	encoders := format.NewEncoderCollection(encs...)
	encoder := encoders.GetByString(opts.Outputs[0])
	if encoder == nil {
		return fmt.Errorf("unable to find encoder for %q", opts.Outputs[0])
	}

	if err = encoder.Encode(sbomFile, *s); err != nil {
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}

	return nil
}

func createAttestation(sbomFilepath string, opts *attestOptions, userInput string) error {
	execCmd, err := attestCommand(sbomFilepath, opts, userInput)
	if err != nil {
		return fmt.Errorf("unable to craft attest command: %w", err)
	}

	log.WithFields("cmd", strings.Join(execCmd.Args, " ")).Trace("creating attestation")

	// bus adapter for ui to hook into stdout via an os pipe
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("unable to create os pipe: %w", err)
	}
	defer w.Close()

	mon := progress.NewManual(-1)

	bus.Publish(
		partybus.Event{
			Type: event.AttestationStarted,
			Source: monitor.GenericTask{
				Title: monitor.Title{
					Default:      "Create attestation",
					WhileRunning: "Creating attestation",
					OnSuccess:    "Created attestation",
				},
				Context: "cosign",
			},
			Value: &monitor.ShellProgress{
				Reader:       r,
				Progressable: mon,
			},
		},
	)

	execCmd.Stdout = w
	execCmd.Stderr = w

	// attest the SBOM
	err = execCmd.Run()
	if err != nil {
		mon.SetError(err)
		return fmt.Errorf("unable to attest SBOM: %w", err)
	}

	mon.SetCompleted()
	return nil
}

func attestCommand(sbomFilepath string, opts *attestOptions, userInput string) (*exec.Cmd, error) {
	outputNames := opts.OutputNameSet()
	var outputName string
	switch outputNames.Size() {
	case 0:
		return nil, fmt.Errorf("no output format specified")
	case 1:
		outputName = outputNames.List()[0]
	default:
		return nil, fmt.Errorf("multiple output formats specified: %s", strings.Join(outputNames.List(), ", "))
	}

	args := []string{"attest", userInput, "--predicate", sbomFilepath, "--type", predicateType(outputName), "-y"}
	if opts.Attest.Key != "" {
		args = append(args, "--key", opts.Attest.Key.String())
	}

	execCmd := exec.Command(cosignBinName, args...)
	execCmd.Env = os.Environ()
	if opts.Attest.Key != "" {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("COSIGN_PASSWORD=%s", opts.Attest.Password))
	} else {
		// no key provided, use cosign's keyless mode
		execCmd.Env = append(execCmd.Env, "COSIGN_EXPERIMENTAL=1")
	}

	return execCmd, nil
}

func predicateType(outputName string) string {
	// select the Cosign predicate type based on defined output type
	// As orientation, check: https://github.com/sigstore/cosign/blob/main/pkg/cosign/attestation/attestation.go
	switch strings.ToLower(outputName) {
	case "cyclonedx-json":
		return "cyclonedx"
	case "spdx-tag-value", "spdx-tv":
		return "spdx"
	case "spdx-json", "json":
		return "spdxjson"
	default:
		return "custom"
	}
}

func generateSBOMForAttestation(ctx context.Context, id clio.Identification, opts *options.Catalog, userInput string) (*sbom.SBOM, error) {
	if len(opts.From) > 1 || (len(opts.From) == 1 && opts.From[0] != stereoscope.RegistryTag) {
		return nil, fmt.Errorf("attest requires use of an OCI registry directly, one or more of the specified sources is unsupported: %v", opts.From)
	}

	src, err := getSource(ctx, opts, userInput, stereoscope.RegistryTag)

	if err != nil {
		return nil, err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := generateSBOM(ctx, id, src, opts)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, fmt.Errorf("no SBOM produced for %q", userInput)
	}

	return s, nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
