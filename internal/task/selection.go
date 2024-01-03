package task

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

// Selection represents the users request for a subset of tasks to run and the resulting set of task names that were
// selected. Additionally, all tokens that were matched on to reach the returned conclusion are also provided.
type Selection struct {
	Request      pkgcataloging.SelectionRequest
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
func Select(allTasks []Task, selectionRequest pkgcataloging.SelectionRequest) ([]Task, Selection, error) {
	nodes := newExpressionsFromSelectionRequest(newExpressionContext(allTasks), selectionRequest)

	finalTasks, selection := selectByExpressions(allTasks, nodes)

	selection.Request = selectionRequest

	return finalTasks, selection, nodes.Validate()
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
