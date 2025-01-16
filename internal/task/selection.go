package task

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
)

// Selection represents the users request for a subset of tasks to run and the resulting set of task names that were
// selected. Additionally, all tokens that were matched on to reach the returned conclusion are also provided.
type Selection struct {
	Request      cataloging.SelectionRequest
	Result       *strset.Set
	TokensByTask map[string]TokenSelection
}

// TokenSelection represents the tokens that were matched on to either include or exclude a given task (based on expression evaluation).
type TokenSelection struct {
	SelectedOn   *strset.Set
	DeselectedOn *strset.Set
}

func newTokenSelection(selected, deselected []string) TokenSelection {
	return TokenSelection{
		SelectedOn:   strset.New(selected...),
		DeselectedOn: strset.New(deselected...),
	}
}

func (ts *TokenSelection) merge(other ...TokenSelection) {
	for _, o := range other {
		if ts.SelectedOn != nil {
			ts.SelectedOn.Add(o.SelectedOn.List()...)
		}
		if ts.DeselectedOn != nil {
			ts.DeselectedOn.Add(o.DeselectedOn.List()...)
		}
	}
}

func newSelection() Selection {
	return Selection{
		Result:       strset.New(),
		TokensByTask: make(map[string]TokenSelection),
	}
}

// Select parses the given expressions as two sets: expressions that represent a "set" operation, and expressions that
// represent all other operations. The parsed expressions are then evaluated against the given tasks to return
// a subset (or the same) set of tasks.
func Select(allTasks []Task, selectionRequest cataloging.SelectionRequest) ([]Task, Selection, error) {
	ensureDefaultSelectionHasFiles(&selectionRequest, allTasks)

	return _select(allTasks, selectionRequest)
}

func _select(allTasks []Task, selectionRequest cataloging.SelectionRequest) ([]Task, Selection, error) {
	if selectionRequest.IsEmpty() {
		selection := newSelection()
		selection.Request = selectionRequest
		return nil, selection, nil
	}
	nodes := newExpressionsFromSelectionRequest(newExpressionContext(allTasks), selectionRequest)

	finalTasks, selection := selectByExpressions(allTasks, nodes)

	selection.Request = selectionRequest

	return finalTasks, selection, nodes.Validate()
}

// ensureDefaultSelectionHasFiles ensures that the default selection request has the "file" tag, as this is a required
// for backwards compatibility (when catalogers were only for packages and not for separate groups of tasks).
func ensureDefaultSelectionHasFiles(selectionRequest *cataloging.SelectionRequest, allTasks ...[]Task) {
	for _, ts := range allTasks {
		_, leftOver := tagsOrNamesThatTaskGroupRespondsTo(ts, strset.New(filecataloging.FileTag))
		if leftOver.Has(filecataloging.FileTag) {
			// the given set of tasks do not respond to file, so don't include it in the default selection
			continue
		}

		defaultNamesOrTags := strset.New(selectionRequest.DefaultNamesOrTags...)
		removals := strset.New(selectionRequest.RemoveNamesOrTags...)
		missingFileIshTag := !defaultNamesOrTags.Has(filecataloging.FileTag) && !defaultNamesOrTags.Has("all") && !defaultNamesOrTags.Has("default")
		if missingFileIshTag && !removals.Has(filecataloging.FileTag) {
			log.Warnf("adding '%s' tag to the default cataloger selection, to override add '-%s' to the cataloger selection request", filecataloging.FileTag, filecataloging.FileTag)
			selectionRequest.DefaultNamesOrTags = append(selectionRequest.DefaultNamesOrTags, filecataloging.FileTag)
		}
	}
}

// SelectInGroups is a convenience function that allows for selecting tasks from multiple groups of tasks. The original
// request is split into sub-requests, where only tokens that are relevant to the given group of tasks are considered.
// If tokens are passed that are not relevant to any group of tasks, an error is returned.
func SelectInGroups(taskGroups [][]Task, selectionRequest cataloging.SelectionRequest) ([][]Task, Selection, error) {
	ensureDefaultSelectionHasFiles(&selectionRequest, taskGroups...)

	reqs, errs := splitCatalogerSelectionRequest(selectionRequest, taskGroups)
	if errs != nil {
		return nil, Selection{
			Request: selectionRequest,
		}, errs
	}

	var finalTasks [][]Task
	var selections []Selection
	for idx, req := range reqs {
		tskGroup := taskGroups[idx]
		subFinalTasks, subSelection, err := _select(tskGroup, req)
		if err != nil {
			return nil, Selection{
				Request: selectionRequest,
			}, err
		}
		finalTasks = append(finalTasks, subFinalTasks)
		selections = append(selections, subSelection)
	}

	return finalTasks, mergeSelections(selections, selectionRequest), nil
}

func mergeSelections(selections []Selection, ogRequest cataloging.SelectionRequest) Selection {
	finalSelection := newSelection()
	for _, s := range selections {
		finalSelection.Result.Add(s.Result.List()...)
		for name, tokenSelection := range s.TokensByTask {
			if existing, exists := finalSelection.TokensByTask[name]; exists {
				existing.merge(tokenSelection)
				finalSelection.TokensByTask[name] = existing
			} else {
				finalSelection.TokensByTask[name] = tokenSelection
			}
		}
	}
	finalSelection.Request = ogRequest
	return finalSelection
}

func splitCatalogerSelectionRequest(req cataloging.SelectionRequest, selectablePkgTaskGroups [][]Task) ([]cataloging.SelectionRequest, error) {
	requestTagsOrNames := allRequestReferences(req)
	leftoverTags := strset.New()
	usedTagsAndNames := strset.New()
	var usedTagGroups []*strset.Set
	for _, taskGroup := range selectablePkgTaskGroups {
		selectedTagOrNames, remainingTagsOrNames := tagsOrNamesThatTaskGroupRespondsTo(taskGroup, requestTagsOrNames)
		leftoverTags = strset.Union(leftoverTags, remainingTagsOrNames)
		usedTagGroups = append(usedTagGroups, selectedTagOrNames)
		usedTagsAndNames.Add(selectedTagOrNames.List()...)
	}

	leftoverTags = strset.Difference(leftoverTags, usedTagsAndNames)
	leftoverTags.Remove("all")

	if leftoverTags.Size() > 0 {
		l := leftoverTags.List()
		sort.Strings(l)
		return nil, fmt.Errorf("no cataloger tasks respond to the following selections: %v", strings.Join(l, ", "))
	}

	var newSelections []cataloging.SelectionRequest
	for _, tags := range usedTagGroups {
		newSelections = append(newSelections, newSelectionWithTags(req, tags))
	}

	return newSelections, nil
}

func newSelectionWithTags(req cataloging.SelectionRequest, tags *strset.Set) cataloging.SelectionRequest {
	return cataloging.SelectionRequest{
		DefaultNamesOrTags: filterTags(req.DefaultNamesOrTags, tags),
		SubSelectTags:      filterTags(req.SubSelectTags, tags),
		AddNames:           filterTags(req.AddNames, tags),
		RemoveNamesOrTags:  filterTags(req.RemoveNamesOrTags, tags),
	}
}

func filterTags(reqTags []string, filterTags *strset.Set) []string {
	var filtered []string
	for _, tag := range reqTags {
		if filterTags.Has(tag) {
			filtered = append(filtered, tag)
		}
	}
	return filtered
}

func tagsOrNamesThatTaskGroupRespondsTo(tasks []Task, requestTagsOrNames *strset.Set) (*strset.Set, *strset.Set) {
	positiveRefs := strset.New()
	for _, t := range tasks {
		if sel, ok := t.(Selector); ok {
			positiveRefs.Add("all") // everything responds to "all"
			positiveRefs.Add(strset.Intersection(requestTagsOrNames, strset.New(sel.Selectors()...)).List()...)
		}
		positiveRefs.Add(t.Name())
	}
	return positiveRefs, strset.Difference(requestTagsOrNames, positiveRefs)
}

func allRequestReferences(s cataloging.SelectionRequest) *strset.Set {
	st := strset.New()
	st.Add(s.DefaultNamesOrTags...)
	st.Add(s.SubSelectTags...)
	st.Add(s.AddNames...)
	st.Add(s.RemoveNamesOrTags...)
	return st
}

// selectByExpressions the set of tasks to run based on the given expression(s).
func selectByExpressions(ts tasks, nodes Expressions) (tasks, Selection) {
	if len(nodes) == 0 {
		return ts, newSelection()
	}

	finalSet := newSet()
	selectionSet := newSet()
	addSet := newSet()
	removeSet := newSet()

	allSelections := make(map[string]TokenSelection)

	nodes = nodes.Clone()
	sort.Sort(nodes)

	for i, node := range nodes {
		if len(node.Errors) > 0 {
			continue
		}
		selectedTasks, selections := evaluateExpression(ts, node)

		for name, ss := range selections {
			if selection, exists := allSelections[name]; exists {
				ss.merge(selection)
			}
			allSelections[name] = ss
		}

		if len(selectedTasks) == 0 {
			log.WithFields("selection", fmt.Sprintf("%q", node.String())).Warn("no cataloger tasks selected found for given selection (this might be a misconfiguration)")
		}

		switch node.Operation {
		case SetOperation:
			finalSet.Add(selectedTasks...)
		case AddOperation, "":
			addSet.Add(selectedTasks...)
		case RemoveOperation:
			removeSet.Add(selectedTasks...)
		case SubSelectOperation:
			selectionSet.Add(selectedTasks...)
		default:
			nodes[i].Errors = append(nodes[i].Errors, ErrInvalidOperator)
		}
	}

	if len(selectionSet.tasks) > 0 {
		finalSet.Intersect(selectionSet.Tasks()...)
	}
	finalSet.Remove(removeSet.Tasks()...)
	finalSet.Add(addSet.Tasks()...)

	finalTasks := finalSet.Tasks()

	return finalTasks, Selection{
		Result:       strset.New(finalTasks.Names()...),
		TokensByTask: allSelections,
	}
}

// evaluateExpression returns the set of tasks that match the given expression (as well as all tokens that were matched
// on to reach the returned conclusion).
func evaluateExpression(ts tasks, node Expression) ([]Task, map[string]TokenSelection) {
	selection := make(map[string]TokenSelection)
	var finalTasks []Task

	for _, t := range ts {
		if !isSelected(t, node.Operand) {
			continue
		}

		s := newTokenSelection(nil, nil)

		switch node.Operation {
		case SetOperation, SubSelectOperation, AddOperation:
			s.SelectedOn.Add(node.Operand)
		case RemoveOperation:
			s.DeselectedOn.Add(node.Operand)
		}

		finalTasks = append(finalTasks, t)

		if og, exists := selection[t.Name()]; exists {
			s.merge(og)
		}

		selection[t.Name()] = s
	}
	return finalTasks, selection
}

// isSelected returns true if the given task matches the given token. If the token is "all" then the task is always selected.
func isSelected(td Task, token string) bool {
	if token == "all" {
		return true
	}

	if ts, ok := td.(Selector); ok {
		// use the selector to verify all tags
		if ts.HasAllSelectors(token) {
			return true
		}
	}

	// only do exact name matching
	if td.Name() == token {
		return true
	}

	return false
}
