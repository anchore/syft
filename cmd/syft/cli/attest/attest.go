package attest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"golang.org/x/exp/slices"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(_ context.Context, app *config.Application, args []string) error {
	err := ValidateOutputOptions(app)
	if err != nil {
		return err
	}

	// note: must be a container image
	userInput := args[0]

	_, err = exec.LookPath("cosign")
	if err != nil {
		// when cosign is not installed the error will be rendered like so:
		// 2023/06/30 08:31:52 error during command execution: 'syft attest' requires cosign to be installed: exec: "cosign": executable file not found in $PATH
		return fmt.Errorf("'syft attest' requires cosign to be installed: %w", err)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, userInput),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func buildSBOM(app *config.Application, userInput string, errs chan error) (*sbom.SBOM, error) {
	cfg := source.DetectConfig{
		DefaultImageSource: app.DefaultImagePullSource,
	}
	detection, err := source.Detect(userInput, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not deteremine source: %w", err)
	}

	if detection.IsContainerImage() {
		return nil, fmt.Errorf("attestations are only supported for oci images at this time")
	}

	var platform *image.Platform

	if app.Platform != "" {
		platform, err = image.NewPlatform(app.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
	}

	hashers, err := file.Hashers(app.Source.File.Digests...)
	if err != nil {
		return nil, fmt.Errorf("invalid hash: %w", err)
	}

	src, err := detection.NewSource(
		source.DetectionSourceConfig{
			Alias: source.Alias{
				Name:    app.Source.Name,
				Version: app.Source.Version,
			},
			RegistryOptions: app.Registry.ToOptions(),
			Platform:        platform,
			Exclude: source.ExcludeConfig{
				Paths: app.Exclusions,
			},
			DigestAlgorithms: hashers,
			BasePath:         app.BasePath,
		},
	)

	if src != nil {
		defer src.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
	}

	s, err := packages.GenerateSBOM(src, errs, app)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, fmt.Errorf("no SBOM produced for %q", userInput)
	}

	return s, nil
}

//nolint:funlen
func execWorker(app *config.Application, userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		defer bus.Exit()

		s, err := buildSBOM(app, userInput, errs)
		if err != nil {
			errs <- fmt.Errorf("unable to build SBOM: %w", err)
			return
		}

		// note: ValidateOutputOptions ensures that there is no more than one output type
		o := app.Outputs[0]

		f, err := os.CreateTemp("", o)
		if err != nil {
			errs <- fmt.Errorf("unable to create temp file: %w", err)
			return
		}
		defer os.Remove(f.Name())

		writer, err := options.MakeSBOMWriter(app.Outputs, f.Name(), app.OutputTemplatePath)
		if err != nil {
			errs <- fmt.Errorf("unable to create SBOM writer: %w", err)
			return
		}

		if err := writer.Write(*s); err != nil {
			errs <- fmt.Errorf("unable to write SBOM to temp file: %w", err)
			return
		}

		// TODO: what other validation here besides binary name?
		cmd := "cosign"
		if !commandExists(cmd) {
			errs <- fmt.Errorf("unable to find cosign in PATH; make sure you have it installed")
			return
		}

		// Select Cosign predicate type based on defined output type
		// As orientation, check: https://github.com/sigstore/cosign/blob/main/pkg/cosign/attestation/attestation.go
		var predicateType string
		switch strings.ToLower(o) {
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
		if app.Attest.Key != "" {
			args = append(args, "--key", app.Attest.Key)
		}

		execCmd := exec.Command(cmd, args...)
		execCmd.Env = os.Environ()
		if app.Attest.Key != "" {
			execCmd.Env = append(execCmd.Env, fmt.Sprintf("COSIGN_PASSWORD=%s", app.Attest.Password))
		} else {
			// no key provided, use cosign's keyless mode
			execCmd.Env = append(execCmd.Env, "COSIGN_EXPERIMENTAL=1")
		}

		log.WithFields("cmd", strings.Join(execCmd.Args, " ")).Trace("creating attestation")

		// bus adapter for ui to hook into stdout via an os pipe
		r, w, err := os.Pipe()
		if err != nil {
			errs <- fmt.Errorf("unable to create os pipe: %w", err)
			return
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
			errs <- fmt.Errorf("unable to attest SBOM: %w", err)
			return
		}

		mon.SetCompleted()
	}()
	return errs
}

func ValidateOutputOptions(app *config.Application) error {
	err := packages.ValidateOutputOptions(app)
	if err != nil {
		return err
	}

	if len(app.Outputs) > 1 {
		return fmt.Errorf("multiple SBOM format is not supported for attest at this time")
	}

	// cannot use table as default output format when using template output
	if slices.Contains(app.Outputs, table.ID.String()) {
		app.Outputs = []string{syftjson.ID.String()}
	}

	return nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
