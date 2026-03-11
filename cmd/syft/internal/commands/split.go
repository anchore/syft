package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/fangs"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/split"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const (
	splitExample = `  {{.appName}} {{.command}} image.sbom.json                              split SBOM into one file per package
  {{.appName}} {{.command}} image.sbom.json --pkg musl                    split only the musl package
  {{.appName}} {{.command}} image.sbom.json --pkg musl --dir /tmp         write output to /tmp directory
  {{.appName}} {{.command}} image.sbom.json --drop source --drop location:fsid  drop source and filesystem IDs
`
)

// SplitOptions defines the options for the split command
type SplitOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	Packages            []string `yaml:"packages" json:"packages" mapstructure:"packages"`
	OutputDir           string   `yaml:"output-dir" json:"output-dir" mapstructure:"output-dir"`
	Drop                []string `yaml:"drop" json:"drop" mapstructure:"drop"`
}

var _ interface {
	clio.FlagAdder
	fangs.FieldDescriber
} = (*SplitOptions)(nil)

func (o *SplitOptions) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Packages, "pkg", "p", "package(s) to split (can be specified multiple times)")
	flags.StringVarP(&o.OutputDir, "dir", "d", "output directory for split SBOMs (default: current directory)")
	flags.StringArrayVarP(&o.Drop, "drop", "", "drop options to apply (source, descriptor, distro, pkg:*, file:*, location:*, all)")
}

func (o *SplitOptions) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&o.Packages, "package queries to match for splitting (ID, PURL, name, or name@version)")
	descriptions.Add(&o.OutputDir, "output directory for split SBOM files")
	descriptions.Add(&o.Drop, "options for dropping SBOM sections (source, descriptor, distro, pkg:licenses, pkg:metadata.files, file:metadata, file:digests, file:executable, file:unknowns, file:licenses, file:contents, location:fsid, location:non-primary-evidence, all)")
}

// Split creates the split command
func Split(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &SplitOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		OutputDir:   ".",
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "split [SOURCE-SBOM] [flags]",
		Short: "Split an SBOM into separate SBOMs per package",
		Long: `[Experimental] Split a syft-format SBOM into one or more SBOMs, one per package.
Each output SBOM contains only the target package, its related packages (connected via
ownership-by-file-overlap and evident-by relationships), and their associated files.

If no --pkg flags are specified, creates one SBOM file per package in the source SBOM.
If --pkg flags are specified, only creates SBOM files for the matching packages.

Package matching (in order of precedence):
  1. Exact package ID
  2. Exact PURL or PURL prefix
  3. Case-insensitive package name
  4. name@version format

Drop options:
  source                         Drop the source object entirely
  descriptor                     Drop the descriptor object
  distro                         Drop the distro (Linux distribution) object
  pkg:licenses                   Drop package licenses
  pkg:metadata.files             Drop files from package metadata (for FileOwner types)
  file:metadata                  Drop file metadata (size, permissions, etc.)
  file:digests                   Drop file digests
  file:executable                Drop executable metadata
  file:unknowns                  Drop unknown file entries
  file:licenses                  Drop file-level licenses
  file:contents                  Drop file contents
  location:fsid                  Clear FileSystemID from all coordinates
  location:non-primary-evidence  Drop locations without "evidence": "primary" annotation
  all                            Apply all drop options above`,
		Example: internal.Tprintf(splitExample, map[string]interface{}{
			"appName": id.Name,
			"command": "split",
		}),
		Args:    validateSplitArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(_ *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return RunSplit(opts, args[0])
		},
	}, opts)
}

func validateSplitArgs(cmd *cobra.Command, args []string) error {
	return validateArgs(cmd, args, "an SBOM argument is required")
}

// RunSplit executes the split operation
func RunSplit(opts *SplitOptions, userInput string) error {
	log.Warn("split is an experimental feature, run `syft split -h` for help")

	// validate drop options
	for _, d := range opts.Drop {
		if !split.ValidDropOption(d) {
			return fmt.Errorf("invalid drop option: %q", d)
		}
	}

	// parse drop options
	dropOpts := split.ParseDropOptions(opts.Drop)
	dropLocationFSID := split.HasDropLocationFSID(dropOpts)
	dropNonPrimaryEvidence := split.HasDropLocationNonPrimaryEvidence(dropOpts)

	// read SBOM
	var reader io.ReadSeekCloser
	if userInput == "-" {
		reader = internal.NewBufferedSeeker(os.Stdin)
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

	s, formatID, _, err := format.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode SBOM: %w", err)
	}

	if s == nil {
		return fmt.Errorf("no SBOM produced")
	}

	// warn if not syft-json format
	if formatID != syftjson.ID {
		log.Warnf("input SBOM is not syft-json format (detected: %s), some data may be lost", formatID)
	}

	// determine target packages
	var targetPackages []pkg.Package
	if len(opts.Packages) == 0 {
		// split all packages
		targetPackages = s.Artifacts.Packages.Sorted()
	} else {
		// match specified packages
		targetPackages = split.MatchPackages(s.Artifacts.Packages, opts.Packages)
		if len(targetPackages) == 0 {
			return fmt.Errorf("no packages matched the specified queries: %v", opts.Packages)
		}
		log.Infof("matched %d package(s) for splitting", len(targetPackages))
	}

	// ensure output directory exists
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// split SBOM
	results := split.Split(*s, targetPackages, dropLocationFSID, dropNonPrimaryEvidence)

	// create encoder
	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{
		Pretty: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}

	// get fields to remove from JSON output
	fieldsToRemove := split.GetJSONFieldsToRemove(dropOpts)

	// write output files
	for _, result := range results {
		// apply drop options (excluding location:* options which are handled in Split)
		filteredDropOpts := make([]split.DropOption, 0, len(dropOpts))
		for _, opt := range dropOpts {
			if opt != split.DropLocationFSID && opt != split.DropLocationNonPrimaryEvidence {
				filteredDropOpts = append(filteredDropOpts, opt)
			}
		}
		split.ApplyDropOptions(&result.SBOM, filteredDropOpts)

		// generate output filename using package ID
		outputFile := filepath.Join(opts.OutputDir, fmt.Sprintf("%s.json", result.TargetPackage.ID()))

		if err := writeSBOMWithFieldRemoval(encoder, result.SBOM, outputFile, fieldsToRemove); err != nil {
			return fmt.Errorf("failed to write SBOM for package %s: %w", result.TargetPackage.Name, err)
		}

		log.Infof("wrote %s (%s@%s)", outputFile, result.TargetPackage.Name, result.TargetPackage.Version)
	}

	log.Infof("split complete: %d SBOM(s) written to %s", len(results), opts.OutputDir)
	return nil
}

func writeSBOMWithFieldRemoval(encoder sbom.FormatEncoder, s sbom.SBOM, outputFile string, fieldsToRemove []string) error {
	// if no fields to remove, use direct encoding
	if len(fieldsToRemove) == 0 {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer func() {
			_ = f.Close()
		}()
		return encoder.Encode(f, s)
	}

	// encode to buffer first
	var buf bytes.Buffer
	if err := encoder.Encode(&buf, s); err != nil {
		return fmt.Errorf("failed to encode SBOM: %w", err)
	}

	// parse as generic map to remove fields
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		return fmt.Errorf("failed to parse encoded SBOM: %w", err)
	}

	// remove specified fields
	for _, field := range fieldsToRemove {
		delete(doc, field)
	}

	// re-encode with pretty printing
	output, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return fmt.Errorf("failed to re-encode SBOM: %w", err)
	}

	// write to file
	if err := os.WriteFile(outputFile, append(output, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
