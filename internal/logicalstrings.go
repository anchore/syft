package internal

import (
	"fmt"
	"strings"
)

type Joiner string

const (
	AND Joiner = "AND"
	OR  Joiner = "OR"
)

// LogicalStrings is a helper type for building logical expressions of strings, which can be combined
// in complex compound ways, with logical AND and OR. If no Joiner is provided, the default is AND.
type LogicalStrings struct {
	Compound []LogicalStrings
	Simple   []string
	Joiner
}

func (l LogicalStrings) Size() int {
	return len(l.Compound) + len(l.Simple)
}

func (l LogicalStrings) String() string {
	size := l.Size()
	if size == 0 {
		return ""
	}
	var parts []string
	// first get the simple
	parts = append(parts, l.Simple...)
	// them get the complex
	for _, e := range l.Compound {
		s := e.String()
		if e.Size() > 1 {
			s = "(" + s + ")"
		}
		parts = append(parts, s)
	}
	joiner := l.Joiner
	if joiner == "" {
		joiner = AND
	}
	return strings.Join(parts, fmt.Sprintf(" %s ", joiner))
}

// Process processes each simple element inside the LogicalStrings through a provided function,
// returning a new LogicalStrings with the fields replaced.
func (l LogicalStrings) Process(f func(string) string) LogicalStrings {
	var new LogicalStrings
	for _, e := range l.Simple {
		new.Simple = append(new.Simple, f(e))
	}
	for _, e := range l.Compound {
		new.Compound = append(new.Compound, e.Process(f))
	}
	return new
}

// Elements returns all the elements of the LogicalStrings, the simple elements at the base of every compound.
func (l LogicalStrings) Elements() []string {
	var elements []string
	elements = append(elements, l.Simple...)
	for _, e := range l.Compound {
		elements = append(elements, e.Elements()...)
	}
	return elements
}

// ParseLogicalStrings parse strings joined by AND or OR, as well as compounded by ( and ), into a LogicalStrings struct
func ParseLogicalStrings(s string) (LogicalStrings, error) {
	var (
		currentExpression string
		expressionStack   []string
		currentLS         LogicalStrings
		lsStack           []LogicalStrings
	)

	for _, c := range s {
		switch c {
		case '(':
			expressionStack = append(expressionStack, currentExpression)
			currentExpression = ""
			lsStack = append(lsStack, currentLS)
			currentLS = LogicalStrings{}
		case ')':
			simple, joiner := parseSimpleExpression(currentExpression)
			currentLS.Simple = append(currentLS.Simple, simple...)
			currentLS.Joiner = joiner
			if len(expressionStack) == 0 {
				return LogicalStrings{}, fmt.Errorf("unbalanced parentheses")
			}
			currentExpression = expressionStack[len(expressionStack)-1]
			expressionStack = expressionStack[:len(expressionStack)-1]
			lastLS := lsStack[len(lsStack)-1]
			lastLS.Compound = append(lastLS.Compound, currentLS)
			lsStack = lsStack[:len(lsStack)-1]
			currentLS = lastLS
		default:
			currentExpression += string(c)
		}
	}
	if currentExpression != "" {
		simple, joiner := parseSimpleExpression(currentExpression)
		currentLS.Simple = append(currentLS.Simple, simple...)
		currentLS.Joiner = joiner
	}
	return currentLS, nil
}

func parseSimpleExpression(s string) ([]string, Joiner) {
	var (
		elements []string
		joiner   Joiner
	)
	for _, e := range strings.Fields(s) {
		if e == "AND" || e == "OR" {
			joiner = Joiner(e)
		} else {
			elements = append(elements, e)
		}
	}
	return elements, joiner
}
