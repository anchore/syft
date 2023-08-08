package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/formats"
)

func RunConvert(opts *ConvertOptions, userInput string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")

	writer, err := options.MakeSBOMWriter(opts.Outputs, opts.File, opts.OutputTemplatePath)
	if err != nil {
		return err
	}

	defer bus.Exit()

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

	s, _, err := formats.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	if s == nil {
		return fmt.Errorf("no SBOM produced")
	}

	if err := writer.Write(*s); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}
