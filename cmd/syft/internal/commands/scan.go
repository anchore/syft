package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

const (
	scanExample = `  {{.appName}} {{.command}} alpine:latest                                a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json                        show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx                   show a CycloneDX formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o cyclonedx-json              show a CycloneDX JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx                        show a SPDX 2.3 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx@2.2                    show a SPDX 2.2 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json                   show a SPDX 2.3 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json@2.2               show a SPDX 2.2 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -vv                            show verbose debug information
  {{.appName}} {{.command}} alpine:latest -o template -t my_format.tmpl  show a SBOM formatted according to given template file

  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, SIF container, or generic filesystem directory
`

	schemeHelpHeader = "You can also explicitly specify the scheme to use:"
	imageSchemeHelp  = `    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag            explicitly use the Docker daemon
    {{.appName}} {{.command}} podman:yourrepo/yourimage:tag            explicitly use the Podman daemon
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag          pull image directly from a registry (no container runtime required)
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar     use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar        use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage                read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} singularity:path/to/yourimage.sif        read directly from a Singularity Image Format (SIF) container on disk
`
	nonImageSchemeHelp = `    {{.appName}} {{.command}} dir:path/to/yourproject                  read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file            read directly from a path on disk (any single file)
`
	scanSchemeHelp = "\n  " + schemeHelpHeader + "\n" + imageSchemeHelp + nonImageSchemeHelp

	scanHelp = scanExample + scanSchemeHelp
)

type scanOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
	Cache               options.Cache `json:"-" yaml:"cache" mapstructure:"cache"`
}

func defaultScanOptions() *scanOptions {
	return &scanOptions{
		Output:      options.DefaultOutput(),
		UpdateCheck: options.DefaultUpdateCheck(),
		Catalog:     options.DefaultCatalog(),
		Cache:       options.DefaultCache(),
	}
}

func Scan(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := defaultScanOptions()

	return app.SetupCommand(&cobra.Command{
		Use:   "scan [SOURCE]",
		Short: "Generate an SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(scanHelp, map[string]interface{}{
			"appName": id.Name,
			"command": "scan",
		}),
		Args:    validateScanArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return runScan(cmd.Context(), id, opts, args[0])
		},
	}, opts)
}

func (o *scanOptions) PostLoad() error {
	return o.validateLegacyOptionsNotUsed()
}

func (o *scanOptions) validateLegacyOptionsNotUsed() error {
	if len(fangs.Flatten(o.Config.ConfigFile)) == 0 {
		return nil
	}

	// check for legacy config file shapes that are no longer valid
	type legacyConfig struct {
		BasePath                        *string `yaml:"base-path" json:"base-path" mapstructure:"base-path"`
		DefaultImagePullSource          *string `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
		ExcludeBinaryOverlapByOwnership *bool   `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"`
		File                            any     `yaml:"file" json:"file" mapstructure:"file"`
	}

	for _, f := range fangs.Flatten(o.Config.ConfigFile) {
		by, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read config file during validations %q: %w", f, err)
		}

		var legacy legacyConfig
		if err := yaml.Unmarshal(by, &legacy); err != nil {
			return fmt.Errorf("unable to parse config file during validations %q: %w", f, err)
		}

		if legacy.DefaultImagePullSource != nil {
			return fmt.Errorf("the config file option 'default-image-pull-source' has been removed, please use 'source.image.default-pull-source' instead")
		}

		if legacy.ExcludeBinaryOverlapByOwnership != nil {
			return fmt.Errorf("the config file option 'exclude-binary-overlap-by-ownership' has been removed, please use 'package.exclude-binary-overlap-by-ownership' instead")
		}

		if legacy.BasePath != nil {
			return fmt.Errorf("the config file option 'base-path' has been removed, please use 'source.base-path' instead")
		}

		if legacy.File != nil && reflect.TypeOf(legacy.File).Kind() == reflect.String {
			return fmt.Errorf("the config file option 'file' has been removed, please use 'outputs' instead")
		}
	}
	return nil
}

func validateScanArgs(cmd *cobra.Command, args []string) error {
	return validateArgs(cmd, args, "an image/directory argument is required")
}

func validateArgs(cmd *cobra.Command, args []string, err string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("%v", err)
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func runScan(ctx context.Context, id clio.Identification, opts *scanOptions, userInput string) error {
	writer, err := opts.SBOMWriter()
	if err != nil {
		return err
	}

	sources := opts.From
	if len(sources) == 0 {
		// extract a scheme if it matches any provider tag; this is a holdover for compatibility, using the --from flag is recommended
		explicitSource, newUserInput := stereoscope.ExtractSchemeSource(userInput, allSourceProviderTags()...)
		if explicitSource != "" {
			sources = append(sources, explicitSource)
			userInput = newUserInput
		}
	}

	src, err := getSource(ctx, &opts.Catalog, userInput, sources...)

	if err != nil {
		return err
	}

	defer func() {
		if src != nil {
			if err := src.Close(); err != nil {
				log.Tracef("unable to close source: %+v", err)
			}
		}
	}()

	s, err := generateSBOM(ctx, id, src, &opts.Catalog)
	if err != nil {
		return err
	}

	if s == nil {
		return fmt.Errorf("no SBOM produced for %q", userInput)
	}

	if err := writer.Write(*s); err != nil {
		return fmt.Errorf("failed to write SBOM: %w", err)
	}

	return nil
}

func getSource(ctx context.Context, opts *options.Catalog, userInput string, sources ...string) (source.Source, error) {
	cfg := syft.DefaultGetSourceConfig().
		WithRegistryOptions(opts.Registry.ToOptions()).
		WithAlias(source.Alias{
			Name:    opts.Source.Name,
			Version: opts.Source.Version,
		}).
		WithExcludeConfig(source.ExcludeConfig{
			Paths: opts.Exclusions,
		}).
		WithBasePath(opts.Source.BasePath).
		WithSources(sources...).
		WithDefaultImagePullSource(opts.Source.Image.DefaultPullSource)

	var err error
	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
		cfg = cfg.WithPlatform(platform)
	}

	if opts.Source.File.Digests != nil {
		hashers, err := file.Hashers(opts.Source.File.Digests...)
		if err != nil {
			return nil, fmt.Errorf("invalid hash algorithm: %w", err)
		}
		cfg = cfg.WithDigestAlgorithms(hashers...)
	}

	src, err := syft.GetSource(ctx, userInput, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not determine source: %w", err)
	}

	return src, nil
}

func generateSBOM(ctx context.Context, id clio.Identification, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	s, err := syft.CreateSBOM(ctx, src, opts.ToSBOMConfig(id))
	if err != nil {
		expErrs := filterExpressionErrors(err)
		notifyExpressionErrors(expErrs)
		return nil, err
	}
	return s, nil
}

func filterExpressionErrors(err error) []task.ErrInvalidExpression {
	if err == nil {
		return nil
	}

	expErrs := processErrors(err)

	return expErrs
}

// processErrors traverses error chains and multierror lists and returns all ErrInvalidExpression errors found
func processErrors(err error) []task.ErrInvalidExpression {
	var result []task.ErrInvalidExpression

	var processError func(...error)
	processError = func(errs ...error) {
		for _, e := range errs {
			// note: using errors.As will result in surprising behavior (since that will traverse the error chain,
			// potentially skipping over nodes in a list of errors)
			if cerr, ok := e.(task.ErrInvalidExpression); ok {
				result = append(result, cerr)
				continue
			}
			var multiErr *multierror.Error
			if errors.As(e, &multiErr) {
				processError(multiErr.Errors...)
			}
		}
	}

	processError(err)

	return result
}

func notifyExpressionErrors(expErrs []task.ErrInvalidExpression) {
	helpText := expressionErrorsHelp(expErrs)
	if helpText == "" {
		return
	}

	bus.Notify(helpText)
}

func expressionErrorsHelp(expErrs []task.ErrInvalidExpression) string {
	// enrich all errors found with CLI hints
	if len(expErrs) == 0 {
		return ""
	}

	sb := strings.Builder{}

	sb.WriteString("Suggestions:\n\n")

	found := false
	for i, expErr := range expErrs {
		help := expressionSuggetions(expErr)
		if help == "" {
			continue
		}
		found = true
		sb.WriteString(help)
		if i != len(expErrs)-1 {
			sb.WriteString("\n")
		}
	}

	if !found {
		return ""
	}

	return sb.String()
}

const expressionHelpTemplate = " ❖ Given expression %q\n%s%s"

func expressionSuggetions(expErr task.ErrInvalidExpression) string {
	if expErr.Err == nil {
		return ""
	}

	hint := getHintPhrase(expErr)
	if hint == "" {
		return ""
	}

	return fmt.Sprintf(expressionHelpTemplate,
		getExpression(expErr),
		indentMsg(getExplanation(expErr)),
		indentMsg(hint),
	)
}

func indentMsg(msg string) string {
	if msg == "" {
		return ""
	}

	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		lines[i] = "   " + line
	}

	return strings.Join(lines, "\n") + "\n"
}

func getExpression(expErr task.ErrInvalidExpression) string {
	flag := "--select-catalogers"
	if expErr.Operation == task.SetOperation {
		flag = "--override-default-catalogers"
	}
	return fmt.Sprintf("%s %s", flag, expErr.Expression)
}

func getExplanation(expErr task.ErrInvalidExpression) string {
	err := expErr.Err
	if errors.Is(err, task.ErrUnknownNameOrTag) {
		noun := ""
		switch expErr.Operation {
		case task.AddOperation:
			noun = "name"
		case task.SubSelectOperation:
			noun = "tag"
		default:
			noun = "name or tag"
		}

		return fmt.Sprintf("However, %q is not a recognized cataloger %s.", trimOperation(expErr.Expression), noun)
	}

	if errors.Is(err, task.ErrNamesNotAllowed) {
		if expErr.Operation == task.SubSelectOperation {
			return "However, " + err.Error() + ".\nIt seems like you are intending to add a cataloger in addition to the default set."
		}
		return "However, " + err.Error() + "."
	}

	if errors.Is(err, task.ErrTagsNotAllowed) {
		return "However, " + err.Error() + ".\nAdding groups of catalogers may result in surprising behavior (create inaccurate SBOMs)."
	}

	if errors.Is(err, task.ErrAllNotAllowed) {
		return "However, you " + err.Error() + ".\nIt seems like you are intending to use all catalogers (which is not recommended)."
	}

	if err != nil {
		return "However, this is not valid: " + err.Error()
	}

	return ""
}

func getHintPhrase(expErr task.ErrInvalidExpression) string {
	if errors.Is(expErr.Err, task.ErrUnknownNameOrTag) {
		return ""
	}

	switch expErr.Operation {
	case task.AddOperation:
		if errors.Is(expErr.Err, task.ErrTagsNotAllowed) {
			return fmt.Sprintf("If you are certain this is what you want to do, use %q instead.", "--override-default-catalogers "+trimOperation(expErr.Expression))
		}

	case task.SubSelectOperation:
		didYouMean := "... Did you mean %q instead?"
		if errors.Is(expErr.Err, task.ErrNamesNotAllowed) {
			return fmt.Sprintf(didYouMean, "--select-catalogers +"+expErr.Expression)
		}

		if errors.Is(expErr.Err, task.ErrAllNotAllowed) {
			return fmt.Sprintf(didYouMean, "--override-default-catalogers "+expErr.Expression)
		}
	}
	return ""
}

func trimOperation(x string) string {
	return strings.TrimLeft(x, "+-")
}

func allSourceProviderTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}
