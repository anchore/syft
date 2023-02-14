package convert

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/formats"
)

func Run(_ context.Context, app *config.Application, args []string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")
	writer, err := options.MakeWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// this can only be a SBOM file
	userInput := args[0]

	var reader io.ReadCloser

	if userInput == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(userInput)
		if err != nil {
			return fmt.Errorf("failed to open SBOM file: %w", err)
		}
		defer func() {
			_ = f.Close()
		}()
		reader = f
	}

	sbom, _, err := formats.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	return writer.Write(*sbom)
}
