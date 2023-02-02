package attest

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"golang.org/x/exp/slices"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	err := ValidateOutputOptions(app)
	if err != nil {
		return err
	}

	writer, err := options.MakeWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return fmt.Errorf("unable to write to report destination: %w", err)
	}

	defer func() {
		if err := writer.Close(); err != nil {
			fmt.Printf("unable to close report destination: %+v", err)
		}
	}()

	// could be an image or a directory, with or without a scheme
	// TODO: validate that source is image
	userInput := args[0]
	si, err := source.ParseInputWithName(userInput, app.Platform, true, app.Name)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	if si.Scheme != source.ImageScheme {
		return fmt.Errorf("attestations are only supported for oci images at this time")
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func buildSBOM(app *config.Application, si source.Input, writer sbom.Writer, errs chan error) ([]byte, error) {
	src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
	}

	s, err := packages.GenerateSBOM(src, errs, app)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, fmt.Errorf("no SBOM produced for %q", si.UserInput)
	}

	// note: only works for single format no multi writer support
	sBytes, err := writer.Bytes(*s)
	if err != nil {
		return nil, fmt.Errorf("unable to build SBOM bytes: %w", err)
	}

	return sBytes, nil
}

//nolint:funlen
func execWorker(app *config.Application, si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		sBytes, err := buildSBOM(app, si, writer, errs)
		if err != nil {
			errs <- fmt.Errorf("unable to build SBOM: %w", err)
			return
		}

		// TODO: add multi writer support
		for _, o := range app.Outputs {
			f, err := os.CreateTemp("", o)
			if err != nil {
				errs <- fmt.Errorf("unable to create temp file: %w", err)
				return
			}

			defer f.Close()
			defer os.Remove(f.Name())

			if _, err := f.Write(sBytes); err != nil {
				errs <- fmt.Errorf("unable to write SBOM to temp file: %w", err)
				return
			}

			// TODO: what other validation here besides binary name?
			cmd := "cosign"
			if !commandExists(cmd) {
				errs <- fmt.Errorf("unable to find cosign in PATH; make sure you have it installed")
				return
			}

			args := []string{"attest", si.UserInput, "--predicate", f.Name()}
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

			// bus adapter for ui to hook into stdout via an os pipe
			r, w, err := os.Pipe()
			if err != nil {
				errs <- fmt.Errorf("unable to create os pipe: %w", err)
				return
			}
			defer w.Close()

			b := &busWriter{r: r, w: w, mon: &progress.Manual{N: -1}}
			execCmd.Stdout = b
			execCmd.Stderr = b
			defer b.mon.SetCompleted()

			// attest the SBOM
			err = execCmd.Run()
			if err != nil {
				b.mon.Err = err
				errs <- fmt.Errorf("unable to attest SBOM: %w", err)
				return
			}
		}

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return nil },
		})
	}()
	return errs
}

func ValidateOutputOptions(app *config.Application) error {
	var usesTemplateOutput bool
	for _, o := range app.Outputs {
		if o == template.ID.String() {
			usesTemplateOutput = true
			break
		}
	}

	if usesTemplateOutput && app.OutputTemplatePath == "" {
		return fmt.Errorf(`must specify path to template file when using "template" output format`)
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

type busWriter struct {
	w          *os.File
	r          *os.File
	hasWritten bool
	mon        *progress.Manual
}

func (b *busWriter) Write(p []byte) (n int, err error) {
	if !b.hasWritten {
		b.hasWritten = true
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
					Reader: b.r,
					Manual: b.mon,
				},
			},
		)
	}
	return b.w.Write(p)
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
