package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	_ "github.com/anchore/syft/syft/pkg/cataloger" // register all cataloger capabilities, otherwise the info command will not function
)

var (
	yesStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // hi green
	noStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dark grey
	criteriaWidth  = 60
	criteriaMargin = 10
)

// types for JSON cataloger info output
type (
	configFieldInfo struct {
		Key         string `json:"key"`
		Description string `json:"description"`
		AppKey      string `json:"app_key,omitempty"`
	}

	configInfo struct {
		Type   string            `json:"type"`
		Fields []configFieldInfo `json:"fields,omitempty"`
	}

	detectorPackageInfo struct {
		Class string   `json:"class"`
		Name  string   `json:"name"`
		PURL  string   `json:"purl"`
		CPEs  []string `json:"cpes"`
		Type  string   `json:"type"`
	}

	patternInfo struct {
		Method          string                           `json:"method"`
		Criteria        []string                         `json:"criteria"`
		Conditions      []capabilities.DetectorCondition `json:"conditions,omitempty"`
		Packages        []detectorPackageInfo            `json:"packages,omitempty"`
		Comment         string                           `json:"comment,omitempty"`
		PackageTypes    []string                         `json:"package_types,omitempty"`
		JSONSchemaTypes []string                         `json:"json_schema_types,omitempty"`
		Capabilities    capabilities.CapabilitySet       `json:"capabilities,omitempty"`
	}

	catalogerInfo struct {
		Ecosystem    string                     `json:"ecosystem,omitempty"`
		Name         string                     `json:"name"`
		Type         string                     `json:"type"`
		Selectors    []string                   `json:"selectors,omitempty"`
		Deprecated   bool                       `json:"deprecated,omitempty"`
		Patterns     []patternInfo              `json:"patterns,omitempty"`
		Capabilities capabilities.CapabilitySet `json:"capabilities,omitempty"`
		Config       *configInfo                `json:"config,omitempty"`
	}
)

type catalogerInfoOptions struct {
	Output                     string `yaml:"output" json:"output" mapstructure:"output"`
	options.CatalogerSelection `yaml:",inline" json:",inline" mapstructure:",squash"`
	Names                      []string // cataloger names from args
}

func (o *catalogerInfoOptions) setNames(args []string) error {
	o.Names = args

	usingLegacyCatalogers := len(o.Catalogers) > 0
	usingNewCatalogers := len(o.DefaultCatalogers) > 0 || len(o.SelectCatalogers) > 0
	usingSelection := usingNewCatalogers || usingLegacyCatalogers

	if usingSelection && len(o.Names) > 0 {
		return fmt.Errorf("cannot use both cataloger name arguments and '--catalogers'/'--select-catalogers'/'--default-catalogers' flags")
	}

	if usingSelection {
		// get all available package cataloger tasks
		pkgTaskFactories := task.DefaultPackageTaskFactories()
		allPkgTasks, err := pkgTaskFactories.Tasks(task.DefaultCatalogingFactoryConfig())
		if err != nil {
			return fmt.Errorf("unable to create pkg cataloger tasks: %w", err)
		}

		// make the selection based on user input
		defaultCatalogers := options.FlattenAndSort(o.DefaultCatalogers)
		selectCatalogers := options.FlattenAndSort(o.SelectCatalogers)
		selectedTaskGroups, _, err := task.SelectInGroups(
			[][]task.Task{allPkgTasks},
			cataloging.NewSelectionRequest().
				WithDefaults(defaultCatalogers...).
				WithExpression(selectCatalogers...),
		)

		if err != nil {
			return fmt.Errorf("unable to select catalogers: %w", err)
		}

		// build the list of cataloger names based on the selection
		for _, g := range selectedTaskGroups {
			for _, t := range g {
				o.Names = append(o.Names, t.Name())
			}
		}
	}
	return nil
}

func (o *catalogerInfoOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to output the cataloger info (available: table, json)")
}

func defaultCatalogerCapsOptions() *catalogerInfoOptions {
	return &catalogerInfoOptions{
		CatalogerSelection: options.CatalogerSelection{
			// this is different than the default behavior where a scan will automatically detect the default set
			DefaultCatalogers: []string{"all"},
		},
	}
}

func CatalogerCaps(app clio.Application) *cobra.Command {
	opts := defaultCatalogerCapsOptions()

	return app.SetupCommand(&cobra.Command{
		Use:     "info [OPTIONS] [CATALOGER_NAMES...]",
		Short:   "Show detailed capabilities of catalogers",
		Args:    cobra.ArbitraryArgs,
		PreRunE: disableUI(app, os.Stdout),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := opts.setNames(args); err != nil {
				return err
			}

			return runCatalogerInfo(opts)
		},
	}, opts)
}

func runCatalogerInfo(opts *catalogerInfoOptions) error {
	doc, err := capabilities.LoadDocument()
	if err != nil {
		return fmt.Errorf("unable to load cataloger capabilities: %w", err)
	}

	// filter by cataloger names if provided
	catalogers := doc.Catalogers
	if len(opts.Names) > 0 {
		catalogers = filterCatalogersByName(catalogers, opts.Names)
	}

	report, err := catalogerInfoReport(opts, doc, catalogers)
	if err != nil {
		return fmt.Errorf("unable to generate cataloger info report: %w", err)
	}

	bus.Report(report)
	bus.Notify("Note: the `cataloger info` command is experimental and may change or be removed without notice. Do not depend on its output in production systems.")

	return nil
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

func catalogerInfoReport(opts *catalogerInfoOptions, doc *capabilities.Document, catalogers []capabilities.CatalogerEntry) (string, error) {
	switch opts.Output {
	case jsonFormat:
		return renderCatalogerInfoJSON(doc, catalogers)
	case "table", "":
		return renderCatalogerInfoTable(doc, catalogers), nil
	default:
		return "", fmt.Errorf("invalid output format %q, must be one of: table, json", opts.Output)
	}
}

func renderCatalogerInfoJSON(doc *capabilities.Document, catalogers []capabilities.CatalogerEntry) (string, error) {
	type document struct {
		Catalogers []catalogerInfo `json:"catalogers"`
	}

	docOut := document{}

	// sort catalogers by ecosystem then name
	sort.Slice(catalogers, func(i, j int) bool {
		if catalogers[i].Ecosystem != catalogers[j].Ecosystem {
			return catalogers[i].Ecosystem < catalogers[j].Ecosystem
		}
		return catalogers[i].Name < catalogers[j].Name
	})

	for _, cat := range catalogers {
		info := catalogerInfo{
			Ecosystem:  cat.Ecosystem,
			Name:       cat.Name,
			Type:       cat.Type,
			Selectors:  cat.Selectors,
			Deprecated: isDeprecatedCataloger(cat.Selectors),
		}

		// convert parsers to patterns if available
		info.Patterns = convertParsersToPatterns(cat.Parsers)

		// if no parsers, use detectors instead
		if len(info.Patterns) == 0 {
			info.Capabilities = cat.Capabilities
			info.Patterns = convertDetectorsToPatterns(cat.Detectors, cat.PackageTypes, cat.JSONSchemaTypes)
		}

		info.Config = getConfigInfoFromDocument(doc, cat.Config)

		docOut.Catalogers = append(docOut.Catalogers, info)
	}

	by, err := json.Marshal(docOut)
	return string(by), err
}

// isDeprecatedCataloger checks if a cataloger is deprecated based on its selectors
func isDeprecatedCataloger(selectors []string) bool {
	for _, selector := range selectors {
		if selector == "deprecated" {
			return true
		}
	}
	return false
}

// convertDetectorPackages converts detector package info to the JSON output format
func convertDetectorPackages(pkgs []capabilities.DetectorPackageInfo) []detectorPackageInfo {
	var result []detectorPackageInfo
	for _, pkg := range pkgs {
		result = append(result, detectorPackageInfo{
			Class: pkg.Class,
			Name:  pkg.Name,
			PURL:  pkg.PURL,
			CPEs:  pkg.CPEs,
			Type:  pkg.Type,
		})
	}
	return result
}

// convertParsersToPatterns converts parser entries to pattern info for JSON output
func convertParsersToPatterns(parsers []capabilities.Parser) []patternInfo {
	var patterns []patternInfo
	for _, parser := range parsers {
		patterns = append(patterns, patternInfo{
			Method:          string(parser.Detector.Method),
			Criteria:        parser.Detector.Criteria,
			Conditions:      parser.Detector.Conditions,
			Packages:        convertDetectorPackages(parser.Detector.Packages),
			Comment:         parser.Detector.Comment,
			PackageTypes:    parser.PackageTypes,
			JSONSchemaTypes: parser.JSONSchemaTypes,
			Capabilities:    parser.Capabilities,
		})
	}
	return patterns
}

// convertDetectorsToPatterns converts detector entries to pattern info for JSON output (for non-parser catalogers)
func convertDetectorsToPatterns(detectors []capabilities.Detector, packageTypes, jsonSchemaTypes []string) []patternInfo {
	var patterns []patternInfo
	for _, det := range detectors {
		patterns = append(patterns, patternInfo{
			Method:          string(det.Method),
			Criteria:        det.Criteria,
			Conditions:      det.Conditions,
			Packages:        convertDetectorPackages(det.Packages),
			Comment:         det.Comment,
			PackageTypes:    packageTypes,
			JSONSchemaTypes: jsonSchemaTypes,
		})
	}
	return patterns
}

// getConfigInfoFromDocument retrieves config info from the capabilities document
func getConfigInfoFromDocument(doc *capabilities.Document, configType string) *configInfo {
	if configType == "" {
		return nil
	}
	configEntry, ok := doc.Configs[configType]
	if !ok {
		return nil
	}
	cfg := &configInfo{
		Type: configType,
	}
	for _, field := range configEntry.Fields {
		cfg.Fields = append(cfg.Fields, configFieldInfo{
			Key:         field.Key,
			Description: field.Description,
			AppKey:      field.AppKey,
		})
	}
	return cfg
}

func renderCatalogerInfoTable(_ *capabilities.Document, catalogers []capabilities.CatalogerEntry) string {
	if len(catalogers) == 0 {
		return noStyle.Render("No catalogers found")
	}

	// sort catalogers by ecosystem then name
	sort.Slice(catalogers, func(i, j int) bool {
		if catalogers[i].Ecosystem != catalogers[j].Ecosystem {
			return catalogers[i].Ecosystem < catalogers[j].Ecosystem
		}
		return catalogers[i].Name < catalogers[j].Name
	})

	var buf bytes.Buffer

	// create table with hierarchical merging
	table := tablewriter.NewTable(&buf,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Row: tw.CellConfig{
				Formatting: tw.CellFormatting{MergeMode: tw.MergeHierarchical},
				Alignment:  tw.CellAlignment{Global: tw.AlignLeft},
			},
		}),
	)

	// set headers
	table.Header("ECOSYSTEM", "CATALOGER", "CRITERIA", "LICENSE", "NODES", "EDGES", "KINDS", "LISTING", "DIGESTS", "HASH")

	// build rows for each cataloger
	var data [][]string
	for _, cat := range catalogers {
		ecosystem := cat.Ecosystem
		if ecosystem == "" {
			ecosystem = "other"
		}

		if cat.Type == "generic" {
			// generic catalogers: one row per parser
			for _, parser := range cat.Parsers {
				criteria := formatCriteria([]capabilities.Detector{parser.Detector})
				row := buildTableRowFromCapabilities(ecosystem, cat.Name, criteria, parser.Capabilities)
				data = append(data, row)
			}
		} else {
			// custom catalogers: one row with all detectors
			criteria := formatCriteria(cat.Detectors)
			row := buildTableRowFromCapabilities(ecosystem, cat.Name, criteria, cat.Capabilities)
			data = append(data, row)
		}
	}

	// add all rows at once for better merging
	_ = table.Bulk(data)
	_ = table.Render()
	return buf.String()
}

// buildTableRowFromCapabilities builds a table row from capability values
func buildTableRowFromCapabilities(ecosystem, name, criteria string, caps capabilities.CapabilitySet) []string {
	// extract capability default values
	license := extractBoolCapability(caps, "license")
	nodes := extractNodesCapability(caps)
	edges := extractStringCapability(caps, "dependency.edges")
	kinds := extractArrayCapability(caps, "dependency.kinds")
	listing := extractBoolCapability(caps, "package_manager.files.listing")
	digests := extractBoolCapability(caps, "package_manager.files.digests")
	hash := extractBoolCapability(caps, "package_manager.package_integrity_hash")

	return []string{
		ecosystem,
		name,
		criteria,
		license,
		nodes,
		edges,
		kinds,
		listing,
		digests,
		hash,
	}
}

// extractBoolCapability extracts a boolean capability value and formats it
func extractBoolCapability(caps capabilities.CapabilitySet, name string) string {
	for _, cap := range caps {
		if cap.Name == name {
			if b, ok := cap.Default.(bool); ok {
				if b {
					return yesStyle.Render("✔")
				}
				return noStyle.Render("·")
			}
			return noStyle.Render("·")
		}
	}
	return noStyle.Render("·")
}

// extractStringCapability extracts a string capability value
func extractStringCapability(caps capabilities.CapabilitySet, name string) string {
	for _, cap := range caps {
		if cap.Name == name {
			if s, ok := cap.Default.(string); ok && s != "" {
				return s
			}
			return noStyle.Render("·")
		}
	}
	return noStyle.Render("·")
}

// extractArrayCapability extracts an array capability value and formats it as comma-separated
func extractArrayCapability(caps capabilities.CapabilitySet, name string) string {
	for _, cap := range caps {
		if cap.Name == name {
			// handle various array types
			switch v := cap.Default.(type) {
			case []string:
				if len(v) > 0 {
					return strings.Join(v, ", ")
				}
			case []interface{}:
				if len(v) > 0 {
					strs := make([]string, 0, len(v))
					for _, item := range v {
						strs = append(strs, fmt.Sprintf("%v", item))
					}
					return strings.Join(strs, ", ")
				}
			}
			return noStyle.Render("·")
		}
	}
	return noStyle.Render("·")
}

// extractNodesCapability extracts dependency.depth and formats it
// maps ["direct", "indirect"] to "transitive"
func extractNodesCapability(caps capabilities.CapabilitySet) string {
	for _, cap := range caps {
		if cap.Name == "dependency.depth" {
			switch v := cap.Default.(type) {
			case []string:
				return formatDepthStringArray(v)
			case []interface{}:
				return formatDepthInterfaceArray(v)
			}
			return noStyle.Render("·")
		}
	}
	return noStyle.Render("·")
}

// formatDepthStringArray formats a []string dependency depth value
func formatDepthStringArray(v []string) string {
	if len(v) == 0 {
		return noStyle.Render("·")
	}
	if hasBothDirectAndIndirect(v) {
		return "transitive"
	}
	return strings.Join(v, ", ")
}

// formatDepthInterfaceArray formats a []interface{} dependency depth value
func formatDepthInterfaceArray(v []interface{}) string {
	if len(v) == 0 {
		return noStyle.Render("·")
	}
	strs := make([]string, 0, len(v))
	for _, item := range v {
		strs = append(strs, fmt.Sprintf("%v", item))
	}
	if hasBothDirectAndIndirect(strs) {
		return "transitive"
	}
	return strings.Join(strs, ", ")
}

// hasBothDirectAndIndirect checks if a slice contains both "direct" and "indirect" strings
func hasBothDirectAndIndirect(items []string) bool {
	hasDirect := false
	hasIndirect := false
	for _, item := range items {
		if item == "direct" {
			hasDirect = true
		}
		if item == "indirect" {
			hasIndirect = true
		}
	}
	return hasDirect && hasIndirect
}

func formatCriteria(detectors []capabilities.Detector) string {
	var allCriteria []string
	methods := strset.New()

	for _, det := range detectors {
		allCriteria = append(allCriteria, det.Criteria...)
		methods.Add(string(det.Method))
	}

	// smart word wrapping: wrap by word (criterion) up to criteriaWidth,
	// allow up to criteriaWidth+criteriaMargin before forcing a new line
	var lines []string
	var currentLine []string
	currentLength := 0

	for _, criterion := range allCriteria {
		// calculate length including the criterion plus ", " separator (except for first item)
		itemLength := len(criterion)
		if len(currentLine) > 0 {
			itemLength += 2 // for ", "
		}

		newLength := currentLength + itemLength

		if len(currentLine) > 0 && newLength > criteriaWidth {
			// check if it's within margin
			if newLength <= criteriaWidth+criteriaMargin {
				// close enough, add it anyway
				currentLine = append(currentLine, criterion)
				currentLength = newLength
			} else {
				// too long, finalize current line and start new one
				lines = append(lines, strings.Join(currentLine, ", "))
				currentLine = []string{criterion}
				currentLength = len(criterion)
			}
		} else {
			// fits within width or first item
			currentLine = append(currentLine, criterion)
			currentLength = newLength
		}
	}

	// add final line
	if len(currentLine) > 0 {
		lines = append(lines, strings.Join(currentLine, ", "))
	}

	methodsList := methods.List()
	sort.Strings(methodsList)
	method := strings.Join(methodsList, ", ")

	if len(lines) == 0 {
		return ""
	}

	joined := strings.Join(lines, "\n")
	if method != string(capabilities.GlobDetection) {
		return fmt.Sprintf("%s (%s)", joined, method)
	}
	return joined
}
