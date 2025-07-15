package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
)

var (
	activelyAddedStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // hi green
	deselectedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dark grey
	activelyRemovedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // high red
	defaultStyle           = lipgloss.NewStyle().Underline(true)
	deselectedDefaultStyle = lipgloss.NewStyle().Inherit(deselectedStyle).Underline(true)
)

type catalogerListOptions struct {
	Output            string   `yaml:"output" json:"output" mapstructure:"output"`
	DefaultCatalogers []string `yaml:"default-catalogers" json:"default-catalogers" mapstructure:"default-catalogers"`
	SelectCatalogers  []string `yaml:"select-catalogers" json:"select-catalogers" mapstructure:"select-catalogers"`
	ShowHidden        bool     `yaml:"show-hidden" json:"show-hidden" mapstructure:"show-hidden"`
}

func (o *catalogerListOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to output the cataloger list (available: table, json)")

	flags.StringArrayVarP(&o.DefaultCatalogers, "override-default-catalogers", "", "override the default catalogers with an expression")

	flags.StringArrayVarP(&o.SelectCatalogers, "select-catalogers", "", "select catalogers with an expression")

	flags.BoolVarP(&o.ShowHidden, "show-hidden", "s", "show catalogers that have been de-selected")
}

func defaultCatalogerListOptions() *catalogerListOptions {
	return &catalogerListOptions{
		DefaultCatalogers: []string{"all"},
	}
}

func CatalogerList(app clio.Application) *cobra.Command {
	opts := defaultCatalogerListOptions()

	return app.SetupCommand(&cobra.Command{
		Use:     "list [OPTIONS]",
		Short:   "List available catalogers",
		PreRunE: disableUI(app, os.Stdout),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCatalogerList(opts)
		},
	}, opts)
}

func runCatalogerList(opts *catalogerListOptions) error {
	pkgTaskFactories := task.DefaultPackageTaskFactories()
	fileTaskFactories := task.DefaultFileTaskFactories()
	allPkgTasks, err := pkgTaskFactories.Tasks(task.DefaultCatalogingFactoryConfig())
	if err != nil {
		return fmt.Errorf("unable to create pkg cataloger tasks: %w", err)
	}

	allFileTasks, err := fileTaskFactories.Tasks(task.DefaultCatalogingFactoryConfig())
	if err != nil {
		return fmt.Errorf("unable to create file cataloger tasks: %w", err)
	}

	report, err := catalogerListReport(opts, [][]task.Task{allPkgTasks, allFileTasks})
	if err != nil {
		return fmt.Errorf("unable to generate cataloger list report: %w", err)
	}

	bus.Report(report)

	return nil
}

func catalogerListReport(opts *catalogerListOptions, allTaskGroups [][]task.Task) (string, error) {
	defaultCatalogers := options.Flatten(opts.DefaultCatalogers)
	selectCatalogers := options.Flatten(opts.SelectCatalogers)
	selectedTaskGroups, selectionEvidence, err := task.SelectInGroups(
		allTaskGroups,
		cataloging.NewSelectionRequest().
			WithDefaults(defaultCatalogers...).
			WithExpression(selectCatalogers...),
	)
	if err != nil {
		return "", fmt.Errorf("unable to select catalogers: %w", err)
	}
	var report string

	switch opts.Output {
	case "json":
		report, err = renderCatalogerListJSON(flattenTaskGroups(selectedTaskGroups), selectionEvidence, defaultCatalogers, selectCatalogers)
	case "table", "":
		if opts.ShowHidden {
			report = renderCatalogerListTables(allTaskGroups, selectionEvidence)
		} else {
			report = renderCatalogerListTables(selectedTaskGroups, selectionEvidence)
		}
	}

	if err != nil {
		return "", fmt.Errorf("unable to render cataloger list: %w", err)
	}

	return report, nil
}

func flattenTaskGroups(taskGroups [][]task.Task) []task.Task {
	var allTasks []task.Task
	for _, tasks := range taskGroups {
		allTasks = append(allTasks, tasks...)
	}
	return allTasks
}

func renderCatalogerListJSON(tasks []task.Task, selection task.Selection, defaultSelections, selections []string) (string, error) {
	type node struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	names, tagsByName := extractTaskInfo(tasks)

	nodesByName := make(map[string]node)

	for name := range tagsByName {
		tokensByTask, ok := selection.TokensByTask[name]

		var tagsSelected []string
		if ok {
			tagsSelected = tokensByTask.SelectedOn.List()
		}

		if len(tagsSelected) == 1 && tagsSelected[0] == "all" {
			tagsSelected = tagsByName[name]
		}

		sort.Strings(tagsSelected)

		if tagsSelected == nil {
			// ensure collections are not null
			tagsSelected = []string{}
		}

		nodesByName[name] = node{
			Name: name,
			Tags: tagsSelected,
		}
	}

	type document struct {
		DefaultSelection []string `json:"default"`
		Selection        []string `json:"selection"`
		Catalogers       []node   `json:"catalogers"`
	}

	if selections == nil {
		// ensure collections are not null
		selections = []string{}
	}

	doc := document{
		DefaultSelection: defaultSelections,
		Selection:        selections,
	}

	for _, name := range names {
		doc.Catalogers = append(doc.Catalogers, nodesByName[name])
	}

	by, err := json.Marshal(doc)

	return string(by), err
}

func renderCatalogerListTables(taskGroups [][]task.Task, selection task.Selection) string {
	pkgCatalogerTable := renderCatalogerListTable(taskGroups[0], selection, "Package Cataloger")
	fileCatalogerTable := renderCatalogerListTable(taskGroups[1], selection, "File Cataloger")

	report := fileCatalogerTable + "\n" + pkgCatalogerTable + "\n"

	hasAdditions := len(selection.Request.AddNames) > 0
	hasDefaults := len(selection.Request.DefaultNamesOrTags) > 0
	hasRemovals := len(selection.Request.RemoveNamesOrTags) > 0
	hasSubSelections := len(selection.Request.SubSelectTags) > 0
	expressions := len(selection.Request.SubSelectTags) + len(selection.Request.AddNames) + len(selection.Request.RemoveNamesOrTags)

	var header string

	header += fmt.Sprintf("Default selections: %d\n", len(selection.Request.DefaultNamesOrTags))
	if hasDefaults {
		for _, expr := range selection.Request.DefaultNamesOrTags {
			header += fmt.Sprintf("  • '%s'\n", expr)
		}
	}

	header += fmt.Sprintf("Selection expressions: %d\n", expressions)

	if hasSubSelections {
		for _, n := range selection.Request.SubSelectTags {
			header += fmt.Sprintf("  • '%s' (intersect)\n", n)
		}
	}
	if hasRemovals {
		for _, n := range selection.Request.RemoveNamesOrTags {
			header += fmt.Sprintf("  • '-%s' (remove)\n", n)
		}
	}
	if hasAdditions {
		for _, n := range selection.Request.AddNames {
			header += fmt.Sprintf("  • '+%s' (add)\n", n)
		}
	}

	return header + report
}

func renderCatalogerListTable(tasks []task.Task, selection task.Selection, kindTitle string) string {
	if len(tasks) == 0 {
		return activelyRemovedStyle.Render(fmt.Sprintf("No %ss selected", strings.ToLower(kindTitle)))
	}

	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{kindTitle, "Tags"})

	names, tagsByName := extractTaskInfo(tasks)

	rowsByName := make(map[string]table.Row)

	for name, tags := range tagsByName {
		rowsByName[name] = formatRow(name, tags, selection)
	}

	for _, name := range names {
		t.AppendRow(rowsByName[name])
	}

	report := t.Render()

	return report
}

func formatRow(name string, tags []string, selection task.Selection) table.Row {
	isIncluded := selection.Result.Has(name)
	defaults := strset.New(selection.Request.DefaultNamesOrTags...)
	var selections *task.TokenSelection
	if s, exists := selection.TokensByTask[name]; exists {
		selections = &s
	}

	var formattedTags []string
	for _, tag := range tags {
		formattedTags = append(formattedTags, formatToken(tag, selections, isIncluded, defaults))
	}

	var tagStr string
	if isIncluded {
		tagStr = strings.Join(formattedTags, ", ")
	} else {
		tagStr = strings.Join(formattedTags, deselectedStyle.Render(", "))
	}

	// TODO: selection should keep warnings (non-selections) in struct

	return table.Row{
		formatToken(name, selections, isIncluded, defaults),
		tagStr,
	}
}

func formatToken(token string, selection *task.TokenSelection, included bool, defaults *strset.Set) string {
	if included && selection != nil {
		// format all tokens in selection in green
		if selection.SelectedOn.Has(token) {
			if defaults.Has(token) {
				return defaultStyle.Render(token)
			}
			return activelyAddedStyle.Render(token)
		}

		return token
	}

	// format all tokens in selection in red, all others in grey
	if selection != nil && selection.DeselectedOn.Has(token) {
		return activelyRemovedStyle.Render(token)
	}
	if defaults.Has(token) {
		return deselectedDefaultStyle.Render(token)
	}
	return deselectedStyle.Render(token)
}

func extractTaskInfo(tasks []task.Task) ([]string, map[string][]string) {
	tagsByName := make(map[string][]string)
	var names []string

	for _, tsk := range tasks {
		var tags []string
		name := tsk.Name()

		if s, ok := tsk.(task.Selector); ok {
			set := strset.New(s.Selectors()...)
			set.Remove(name)
			tags = set.List()
			sort.Strings(tags)
		}

		tagsByName[name] = tags
		names = append(names, name)
	}

	sort.Strings(names)

	return names, tagsByName
}
