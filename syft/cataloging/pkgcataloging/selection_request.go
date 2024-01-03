package pkgcataloging

import (
	"strings"
)

type SelectionRequest struct {
	DefaultNamesOrTags []string `json:"default,omitempty"`
	SubSelectTags      []string `json:"selection,omitempty"`
	AddNames           []string `json:"addition,omitempty"`
	RemoveNamesOrTags  []string `json:"removal,omitempty"`
}

func NewSelectionRequest() SelectionRequest {
	return SelectionRequest{}
}

func (s SelectionRequest) WithExpression(expressions ...string) SelectionRequest {
	expressions = cleanSelection(expressions)
	for _, expr := range expressions {
		switch {
		case strings.HasPrefix(expr, "+"):
			s = s.WithAdditions(strings.TrimPrefix(expr, "+"))
		case strings.HasPrefix(expr, "-"):
			s = s.WithRemovals(strings.TrimPrefix(expr, "-"))
		default:
			s = s.WithSubSelections(expr)
		}
	}
	return s
}

func (s SelectionRequest) WithDefaults(nameOrTags ...string) SelectionRequest {
	s.DefaultNamesOrTags = append(s.DefaultNamesOrTags, nameOrTags...)
	return s
}

func (s SelectionRequest) WithSubSelections(tags ...string) SelectionRequest {
	s.SubSelectTags = append(s.SubSelectTags, tags...)
	return s
}

func (s SelectionRequest) WithAdditions(names ...string) SelectionRequest {
	s.AddNames = append(s.AddNames, names...)
	return s
}

func (s SelectionRequest) WithRemovals(nameOrTags ...string) SelectionRequest {
	s.RemoveNamesOrTags = append(s.RemoveNamesOrTags, nameOrTags...)
	return s
}

func cleanSelection(tags []string) []string {
	var cleaned []string
	for _, tag := range tags {
		for _, t := range strings.Split(tag, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			cleaned = append(cleaned, t)
		}
	}
	return cleaned
}
