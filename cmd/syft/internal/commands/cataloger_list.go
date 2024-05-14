package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
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
		Use:   "list [OPTIONS]",
		Short: "List available catalogers",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCatalogerList(opts)
		},
	}, opts)
}

func runCatalogerList(opts *catalogerListOptions) error {
	factories := task.DefaultPackageTaskFactories()
	allTasks, err := factories.Tasks(task.DefaultCatalogingFactoryConfig())
	if err != nil {
		return fmt.Errorf("unable to create cataloger tasks: %w", err)
	}

	report, err := catalogerListReport(opts, allTasks)
	if err != nil {
		return fmt.Errorf("unable to generate cataloger list report: %w", err)
	}

	bus.Report(report)

	return nil
}

func catalogerListReport(opts *catalogerListOptions, allTasks []task.Task) (string, error) {
	selectedTasks, selectionEvidence, err := task.Select(allTasks,
		pkgcataloging.NewSelectionRequest().
			WithDefaults(opts.DefaultCatalogers...).
			WithExpression(opts.SelectCatalogers...),
	)
	if err != nil {
		return "", fmt.Errorf("unable to select catalogers: %w", err)
	}
	var report string

	switch opts.Output {
	case "json":
		report, err = renderCatalogerListJSON(selectedTasks, selectionEvidence, opts.DefaultCatalogers, opts.SelectCatalogers)
	case "table", "":
		if opts.ShowHidden {
			report = renderCatalogerListTable(allTasks, selectionEvidence, opts.DefaultCatalogers, opts.SelectCatalogers)
		} else {
			report = renderCatalogerListTable(selectedTasks, selectionEvidence, opts.DefaultCatalogers, opts.SelectCatalogers)
		}
	}

	if err != nil {
		return "", fmt.Errorf("unable to render cataloger list: %w", err)
	}

	return report, nil
}

func renderCatalogerListJSON(tasks []task.Task, selection task.Selection, defaultSelections, selections []string) (string, error) {
	type node struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	names, tagsByName := extractTaskInfo(tasks)

	nodesByName := make(map[string]node)

	for name := range tagsByName {
		tagsSelected := selection.TokensByTask[name].SelectedOn.List()

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

func renderCatalogerListTable(tasks []task.Task, selection task.Selection, defaultSelections, selections []string) string {
	t := table.NewWriter()
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"Cataloger", "Tags"})

	names, tagsByName := extractTaskInfo(tasks)

	rowsByName := make(map[string]table.Row)

	for name, tags := range tagsByName {
		rowsByName[name] = formatRow(name, tags, selection)
	}

	for _, name := range names {
		t.AppendRow(rowsByName[name])
	}

	report := t.Render()

	if len(selections) > 0 {
		header := "Selected by expressions:\n"
		for _, expr := range selections {
			header += fmt.Sprintf("  - %q\n", expr)
		}
		report = header + report
	}

	if len(defaultSelections) > 0 {
		header := "Default selections:\n"
		for _, expr := range defaultSelections {
			header += fmt.Sprintf("  - %q\n", expr)
		}
		report = header + report
	}

	return report
}

func formatRow(name string, tags []string, selection task.Selection) table.Row {
	isIncluded := selection.Result.Has(name)
	var selections *task.TokenSelection
	if s, exists := selection.TokensByTask[name]; exists {
		selections = &s
	}

	var formattedTags []string
	for _, tag := range tags {
		formattedTags = append(formattedTags, formatToken(tag, selections, isIncluded))
	}

	var tagStr string
	if isIncluded {
		tagStr = strings.Join(formattedTags, ", ")
	} else {
		tagStr = strings.Join(formattedTags, grey.Render(", "))
	}

	// TODO: selection should keep warnings (non-selections) in struct

	return table.Row{
		formatToken(name, selections, isIncluded),
		tagStr,
	}
}

var (
	green = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // hi green
	grey  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dark grey
	red   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // high red
)

func formatToken(token string, selection *task.TokenSelection, included bool) string {
	if included && selection != nil {
		// format all tokens in selection in green
		if selection.SelectedOn.Has(token) {
			return green.Render(token)
		}

		return token
	}

	// format all tokens in selection in red, all others in grey
	if selection != nil && selection.DeselectedOn.Has(token) {
		return red.Render(token)
	}

	return grey.Render(token)
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
