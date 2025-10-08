package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/capabilities"
)

var (
	yesStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // hi green
	noStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dark grey
)

type catalogerInfoOptions struct {
	Output string   `yaml:"output" json:"output" mapstructure:"output"`
	Mode   string   `yaml:"mode" json:"mode" mapstructure:"mode"`
	Names  []string // cataloger names from args
}

func (o *catalogerInfoOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to output the cataloger info (available: table, json)")
	flags.StringVarP(&o.Mode, "mode", "m", "enrichment mode to display (available: offline, online, tool-execution)")
}

func defaultCatalogerInfoOptions() *catalogerInfoOptions {
	return &catalogerInfoOptions{
		Mode: "offline",
	}
}

func CatalogerInfo(app clio.Application) *cobra.Command {
	opts := defaultCatalogerInfoOptions()

	return app.SetupCommand(&cobra.Command{
		Use:     "info [OPTIONS] [CATALOGER_NAMES...]",
		Short:   "Show detailed capabilities of catalogers",
		Args:    cobra.ArbitraryArgs,
		PreRunE: disableUI(app, os.Stdout),
		RunE: func(_ *cobra.Command, args []string) error {
			opts.Names = args
			return runCatalogerInfo(opts)
		},
	}, opts)
}

func runCatalogerInfo(opts *catalogerInfoOptions) error {
	catalogers, err := capabilities.Packages()
	if err != nil {
		return fmt.Errorf("unable to load cataloger capabilities: %w", err)
	}

	mode, err := parseEnrichmentMode(opts.Mode)
	if err != nil {
		return err
	}

	// filter by cataloger names if provided
	if len(opts.Names) > 0 {
		catalogers = filterCatalogersByName(catalogers, opts.Names)
	}

	report, err := catalogerInfoReport(opts, catalogers, mode)
	if err != nil {
		return fmt.Errorf("unable to generate cataloger info report: %w", err)
	}

	bus.Report(report)

	return nil
}

func parseEnrichmentMode(mode string) (capabilities.EnrichmentMode, error) {
	switch mode {
	case "offline":
		return capabilities.OfflineMode, nil
	case "online":
		return capabilities.OnlineMode, nil
	case "tool-execution":
		return capabilities.ToolExecutionMode, nil
	default:
		return "", fmt.Errorf("invalid mode %q, must be one of: offline, online, tool-execution", mode)
	}
}

func filterCatalogersByName(catalogers []capabilities.CatalogerEntry, names []string) []capabilities.CatalogerEntry {
	nameSet := make(map[string]bool)
	for _, name := range names {
		nameSet[name] = true
	}

	var filtered []capabilities.CatalogerEntry
	for _, cat := range catalogers {
		if nameSet[cat.Name] {
			filtered = append(filtered, cat)
		}
	}
	return filtered
}

func catalogerInfoReport(opts *catalogerInfoOptions, catalogers []capabilities.CatalogerEntry, mode capabilities.EnrichmentMode) (string, error) {
	switch opts.Output {
	case jsonFormat:
		return renderCatalogerInfoJSON(catalogers, mode)
	case "table", "":
		return renderCatalogerInfoTable(catalogers, mode), nil
	default:
		return "", fmt.Errorf("invalid output format %q, must be one of: table, json", opts.Output)
	}
}

func renderCatalogerInfoJSON(catalogers []capabilities.CatalogerEntry, mode capabilities.EnrichmentMode) (string, error) {
	type patternInfo struct {
		ParserFunction string                   `json:"parser_function"`
		Method         string                   `json:"method"`
		Criteria       []string                 `json:"criteria"`
		Capability     *capabilities.Capability `json:"capability,omitempty"`
	}

	type catalogerInfo struct {
		Ecosystem  string                   `json:"ecosystem,omitempty"`
		Name       string                   `json:"name"`
		Type       string                   `json:"type"`
		Patterns   []patternInfo            `json:"patterns,omitempty"`
		Capability *capabilities.Capability `json:"capability,omitempty"`
	}

	type document struct {
		Mode       string          `json:"mode"`
		Catalogers []catalogerInfo `json:"catalogers"`
	}

	doc := document{
		Mode: string(mode),
	}

	for _, cat := range catalogers {
		info := catalogerInfo{
			Ecosystem: cat.Ecosystem,
			Name:      cat.Name,
			Type:      cat.Type,
		}

		if cat.Type == "generic" {
			for _, parser := range cat.Parsers {
				pi := patternInfo{
					ParserFunction: parser.ParserFunction,
					Method:         string(parser.Detector.Method),
					Criteria:       parser.Detector.Criteria,
				}
				if capability, ok := parser.Capabilities[mode]; ok {
					pi.Capability = capability
				}
				info.Patterns = append(info.Patterns, pi)
			}
		} else {
			// custom cataloger
			if capability, ok := cat.Capabilities[mode]; ok {
				info.Capability = capability
			}
		}

		doc.Catalogers = append(doc.Catalogers, info)
	}

	by, err := json.Marshal(doc)
	return string(by), err
}

func setupCatalogerInfoTableHeaders(t table.Writer) {
	// Enable horizontal lines between rows
	t.Style().Options.SeparateRows = true

	// Enable vertical merging for specific columns (ecosystem and cataloger)
	// Column indices: 1=Ecosystem, 2=Cataloger
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
	})

	// Create multi-row header with column spanning
	// Row 1: Top-level groups
	// For columns that should span: repeat the same value (Dependencies x3, Package Manager x3)
	t.AppendHeader(table.Row{
		"Ecosystem",
		"Cataloger",
		"Criteria",
		"License",
		"Dependencies",
		"Dependencies",
		"Dependencies",
		"Package Manager",
		"Package Manager",
		"Package Manager",
	}, table.RowConfig{AutoMerge: true})

	// Row 2: Sub-columns
	// Empty strings in first 4 columns will visually merge up with row 1
	t.AppendHeader(table.Row{
		"",
		"",
		"",
		"",
		"Reach",
		"Topology",
		"Kinds",
		"Listing",
		"Digests",
		"Hash",
	})
}

func renderCatalogerInfoTable(catalogers []capabilities.CatalogerEntry, mode capabilities.EnrichmentMode) string {
	if len(catalogers) == 0 {
		return noStyle.Render("No catalogers found")
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	setupCatalogerInfoTableHeaders(t)

	// sort catalogers by ecosystem then name
	sort.Slice(catalogers, func(i, j int) bool {
		if catalogers[i].Ecosystem != catalogers[j].Ecosystem {
			return catalogers[i].Ecosystem < catalogers[j].Ecosystem
		}
		return catalogers[i].Name < catalogers[j].Name
	})

	// append rows with AutoMerge for hierarchical grouping
	for _, cat := range catalogers {
		ecosystem := cat.Ecosystem
		if ecosystem == "" {
			ecosystem = "other"
		}

		if cat.Type == "generic" {
			for _, parser := range cat.Parsers {
				capability := parser.Capabilities[mode]
				criteria := formatCriteria(parser.Detector.Criteria, parser.Detector.Method)
				row := buildTableRow(ecosystem, cat.Name, criteria, capability)
				t.AppendRow(table.Row{
					row[0], row[1], row[2], row[3], row[4],
					row[5], row[6], row[7], row[8], row[9],
				})
			}
		} else {
			// custom cataloger
			capability := cat.Capabilities[mode]
			row := buildTableRow(ecosystem, cat.Name, "N/A", capability)
			t.AppendRow(table.Row{
				row[0], row[1], row[2], row[3], row[4],
				row[5], row[6], row[7], row[8], row[9],
			})
		}
	}

	return t.Render()
}

func formatCriteria(criteria []string, method capabilities.ArtifactDetectionMethod) string {
	// split criteria into groups of 3 with newlines
	var parts []string
	for i := 0; i < len(criteria); i += 3 {
		end := i + 3
		if end > len(criteria) {
			end = len(criteria)
		}
		parts = append(parts, strings.Join(criteria[i:end], ", "))
	}

	joined := strings.Join(parts, "\n")
	if method != capabilities.GlobDetection {
		return fmt.Sprintf("%s (%s)", joined, method)
	}
	return joined
}

func buildTableRow(ecosystem, name, selectors string, capability *capabilities.Capability) []string {
	// default values
	license := formatBool(nil)
	reach := ""
	topology := ""
	kinds := ""
	listing := formatBool(nil)
	digests := formatBool(nil)
	hash := formatBool(nil)

	if capability != nil {
		license = formatBool(capability.License)
		if capability.Dependencies != nil {
			reach = formatStringSlice(capability.Dependencies.Reach)
			topology = capability.Dependencies.Topology
			kinds = formatStringSlice(capability.Dependencies.Kinds)
		}
		if capability.PackageManager != nil {
			if capability.PackageManager.Files != nil {
				listing = formatBool(capability.PackageManager.Files.Listing)
				digests = formatBool(capability.PackageManager.Files.Digests)
			}
			hash = formatBool(capability.PackageManager.PackageIntegrityHash)
		}
	}

	return []string{
		ecosystem,
		name,
		selectors,
		license,
		reach,
		topology,
		kinds,
		listing,
		digests,
		hash,
	}
}

func formatBool(b *bool) string {
	if b == nil {
		return noStyle.Render("-")
	}
	if *b {
		return yesStyle.Render("✔")
	}
	return noStyle.Render("·")
}

func formatStringSlice(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.Join(s, ", ")
}
