package attest

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	err := ValidateOutputOptions(app)
	if err != nil {
		return err
	}
	app.Outputs = []string{"json"}
	app.File = "sbom.json"

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
	userInput := args[0]
	si, err := source.ParseInputWithName(userInput, app.Platform, true, app.Name)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
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

func execWorker(app *config.Application, si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
			return
		}

		s, err := packages.GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			errs <- fmt.Errorf("no SBOM produced for %q", si.UserInput)
		}

		err = writer.Write(*s)
		if err != nil {
			errs <- fmt.Errorf("unable to write SBOM: %w", err)
			return
		}

		// TODO: return error if cannot stat cosign
		// TODO: validate that source is image
		// TODO: cleanup ephemeral file

		cmd := "cosign"
		args := []string{"attest", si.UserInput, "--type", "custom", "--predicate", "sbom.json"}
		execCmd := exec.Command(cmd, args...)
		execCmd.Env = os.Environ()
		// bus adapter for ui to hook into stdout
		execCmd.Env = append(execCmd.Env, "COSIGN_EXPERIMENTAL=1")
		r, w, err := os.Pipe()
		defer w.Close()
		b := &busWriter{r: r, w: w}
		execCmd.Stdout = b
		execCmd.Stderr = b
		err = execCmd.Run()
		// attest the SBOM
		if err != nil {
			errs <- fmt.Errorf("unable to attest SBOM: %w", err)
			return
		}
		// TODO: make sure we validate published attestation is same sbom as what we have on :17

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

	return nil
}

type busWriter struct {
	w          *os.File
	r          *os.File
	hasWritten bool
}

func (b *busWriter) Write(p []byte) (n int, err error) {
	if b.hasWritten == false {
		event := partybus.Event{
			Type:   event.ShellOutput,
			Source: "cosign",
			Value:  b.r,
		}
		b.hasWritten = true
		bus.Publish(event)
	}
	return b.w.Write(p)
}
