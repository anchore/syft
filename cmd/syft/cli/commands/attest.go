package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] alpine:latest defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry
`
	attestSchemeHelp = "\n  " + schemeHelpHeader + "\n" + imageSchemeHelp
	attestHelp       = attestExample + attestSchemeHelp
)

type attestOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
	options.Attest      `yaml:",inline" mapstructure:",squash"`
}

func Attest(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &attestOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Output: options.Output{
			AllowMultipleOutputs: false,
			AllowableOptions: []string{
				string(syftjson.ID),
				string(cyclonedxjson.ID),
				string(spdxjson.ID),
				string(spdxtagvalue.ID),
			},
			Outputs: []string{syftjson.ID.String()},
			OutputFile: options.OutputFile{ // nolint:staticcheck
				Enabled: false, // explicitly not allowed
			},
			OutputTemplate: options.OutputTemplate{
				Enabled: false, // explicitly not allowed
			},
		},
		Catalog: options.DefaultCatalog(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "attest --output [FORMAT] <IMAGE>",
		Short: "Generate an SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation that will be uploaded to the image registry",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
			"appName": id.Name,
			"command": "attest",
		}),
		Args:    validatePackagesArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(id, opts, args[0])
		},
	}, opts)
}

//nolint:funlen
func runAttest(id clio.Identification, opts *attestOptions, userInput string) error {
	_, err := exec.LookPath("cosign")
	if err != nil {
		// when cosign is not installed the error will be rendered like so:
		// 2023/06/30 08:31:52 error during command execution: 'syft attest' requires cosign to be installed: exec: "cosign": executable file not found in $PATH
		return fmt.Errorf("'syft attest' requires cosign to be installed: %w", err)
	}

	s, err := buildSBOM(id, &opts.Catalog, userInput)
	if err != nil {
		return fmt.Errorf("unable to build SBOM: %w", err)
	}

	f, err := os.CreateTemp("", "syft-attest-")
	if err != nil {
		return fmt.Errorf("unable to create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	writer, err := opts.SBOMWriter()
	if err != nil {
		return fmt.Errorf("unable to create SBOM writer: %w", err)
	}

	if err := writer.Write(*s); err != nil {
		return fmt.Errorf("unable to write SBOM to temp file: %w", err)
	}

	// TODO: what other validation here besides binary name?
	cmd := "cosign"
	if !commandExists(cmd) {
		return fmt.Errorf("unable to find cosign in PATH; make sure you have it installed")
	}

	outputNames := opts.OutputNameSet()
	var outputName string
	switch outputNames.Size() {
	case 0:
		return fmt.Errorf("no output format specified")
	case 1:
		outputName = outputNames.List()[0]
	default:
		return fmt.Errorf("multiple output formats specified: %s", strings.Join(outputNames.List(), ", "))
	}

	// Select Cosign predicate type based on defined output type
	// As orientation, check: https://github.com/sigstore/cosign/blob/main/pkg/cosign/attestation/attestation.go
	var predicateType string
	switch strings.ToLower(outputName) {
	case "cyclonedx-json":
		predicateType = "cyclonedx"
	case "spdx-tag-value", "spdx-tv":
		predicateType = "spdx"
	case "spdx-json", "json":
		predicateType = "spdxjson"
	default:
		predicateType = "custom"
	}

	args := []string{"attest", userInput, "--predicate", f.Name(), "--type", predicateType}
	if opts.Attest.Key != "" {
		args = append(args, "--key", opts.Attest.Key.String())
	}

	execCmd := exec.Command(cmd, args...)
	execCmd.Env = os.Environ()
	if opts.Attest.Key != "" {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("COSIGN_PASSWORD=%s", opts.Attest.Password))
	} else {
		// no key provided, use cosign's keyless mode
		execCmd.Env = append(execCmd.Env, "COSIGN_EXPERIMENTAL=1")
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

func buildSBOM(id clio.Identification, opts *options.Catalog, userInput string) (*sbom.SBOM, error) {
	cfg := source.DetectConfig{
		DefaultImageSource: opts.DefaultImagePullSource,
	}
	detection, err := source.Detect(userInput, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not deteremine source: %w", err)
	}

	if detection.IsContainerImage() {
		return nil, fmt.Errorf("attestations are only supported for oci images at this time")
	}

	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
	}

	hashers, err := file.Hashers(opts.Source.File.Digests...)
	if err != nil {
		return nil, fmt.Errorf("invalid hash: %w", err)
	}

	src, err := detection.NewSource(
		source.DetectionSourceConfig{
			Alias: source.Alias{
				Name:    opts.Source.Name,
				Version: opts.Source.Version,
			},
			RegistryOptions: opts.Registry.ToOptions(),
			Platform:        platform,
			Exclude: source.ExcludeConfig{
				Paths: opts.Exclusions,
			},
			DigestAlgorithms: hashers,
			BasePath:         opts.BasePath,
		},
	)

	if src != nil {
		defer src.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
	}

	s, err := generateSBOM(id, src, opts)
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
