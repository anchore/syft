package convert

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")
	writer, err := options.MakeWriter(app.Outputs, app.File)
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
	f, err := os.Open(userInput)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer f.Close()

	sbom, _, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	return writer.Write(*sbom)
}
