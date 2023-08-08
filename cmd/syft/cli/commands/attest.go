package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/github"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/formats/text"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] alpine:latest defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry
`
	attestSchemeHelp = "\n  " + schemeHelpHeader + "\n" + imageSchemeHelp
	attestHelp       = attestExample + attestSchemeHelp
)

type attestOptions struct {
	options.SingleOutput `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck  `yaml:",inline" mapstructure:",squash"`
	options.Packages     `yaml:",inline" mapstructure:",squash"`
	options.Attest       `yaml:",inline" mapstructure:",squash"`
}

func Attest(app clio.Application) *cobra.Command {
	var allowableOutputs []string
	for _, f := range formats.AllIDs() {
		switch f {
		case table.ID, text.ID, github.ID, template.ID:
			continue
		}
		allowableOutputs = append(allowableOutputs, f.String())
	}

	opts := &attestOptions{
		UpdateCheck: options.UpdateCheckDefault(),
		SingleOutput: options.SingleOutput{
			AllowableOptions: allowableOutputs,
			Output:           syftjson.ID.String(),
		},
		Packages: options.PackagesDefault(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "attest --output [FORMAT] <IMAGE>",
		Short: "Generate an SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation that will be uploaded to the image registry",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
			"appName": app.ID().Name,
			"command": "attest",
		}),
		Args: validatePackagesArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.CheckForAppUpdate {
				checkForApplicationUpdate(app)
			}

			return runAttest(app, opts, args[0])
		},
	}, opts)
}
