package convert

import (
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
)

var ConvertibleFormats = []sbom.Format{
	syftjson.Format(),
	spdx22json.Format(),
	spdx22tagvalue.Format(),
	cyclonedxjson.Format(),
	cyclonedxxml.Format(),
}

func Run(ctx context.Context, app *config.Application, args []string) error {
	log.Warn("convert is an experimental feature, run `syft convert -h` for help")
	writer, err := options.MakeWriter(app.Outputs, app.File, ConvertibleFormats...)
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

	sbom, inputFormat, err := syft.Decode(f)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}
	f.Close()

	if !options.IsSupportedFormat(inputFormat.ID(), ConvertibleFormats) {
		return fmt.Errorf("cannot convert from %s format", inputFormat.ID())
	}

	return writer.Write(*sbom)
}
