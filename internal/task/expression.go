package task

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/cataloging"
)

var expressionNodePattern = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9-+]*)+$`)

const (
	SetOperation       Operation = "set"
	AddOperation       Operation = "add"
	SubSelectOperation Operation = "sub-select"
	RemoveOperation    Operation = "remove"
)

var (
	ErrEmptyToken       = fmt.Errorf("no value given")
	ErrInvalidToken     = fmt.Errorf("invalid token given: only alphanumeric characters and hyphens are allowed")
	ErrInvalidOperator  = fmt.Errorf("invalid operator given")
	ErrUnknownNameOrTag = fmt.Errorf("unknown name or tag given")
	ErrTagsNotAllowed   = fmt.Errorf("tags are not allowed with this operation (must use exact names)")
	ErrNamesNotAllowed  = fmt.Errorf("names are not allowed with this operation (must use tags)")
	ErrAllNotAllowed    = fmt.Errorf("cannot use the 'all' operand in this context")
)

// ErrInvalidExpression represents an expression that cannot be parsed or can be parsed but is logically invalid.
type ErrInvalidExpression struct {
	Expression string
	Operation  Operation
	Err        error
}

func (e ErrInvalidExpression) Error() string {
	return fmt.Sprintf("invalid expression: %q: %s", e.Expression, e.Err.Error())
}

func newErrInvalidExpression(exp string, op Operation, err error) ErrInvalidExpression {
	return ErrInvalidExpression{
		Expression: exp,
		Operation:  op,
		Err:        err,
	}
}

// Expression represents a single operation-operand pair with (all validation errors).
// E.g. "+foo", "-bar", or "something" are all expressions. Some validations are relevant to not only the
// syntax (operation and operator) but other are sensitive to the context of the operand (e.g. if a given operand
// is a tag or a name, validated against the operation).
type Expression struct {
	Operation Operation
	Operand   string
	Errors    []error
}

// Operation represents the type of operation to perform on the operand (set, add, remove, sub-select).
type Operation string

// Expressions represents a list of expressions.
type Expressions []Expression

// expressionContext represents all information needed to validate an expression (e.g. the set of all tasks and their tags).
type expressionContext struct {
	Names *strset.Set
	Tags  *strset.Set
}

func newExpressionContext(ts []Task) *expressionContext {
	ec := &expressionContext{
		Names: strset.New(tasks(ts).Names()...),
		Tags:  strset.New(tasks(ts).Tags()...),
	}

	ec.Tags.Add("all")

	return ec
}

// newExpression creates a new validated Expression object relative to the task names and tags.
func (ec expressionContext) newExpression(exp string, operation Operation, token string) Expression {
	if token == "" {
		return Expression{
			Operation: operation,
			Operand:   token,
			Errors:    []error{newErrInvalidExpression(exp, operation, ErrEmptyToken)},
		}
	}

	if !isValidNode(token) {
		return Expression{
			Operation: operation,
			Operand:   token,
			Errors:    []error{newErrInvalidExpression(exp, operation, ErrInvalidToken)},
		}
	}

	var err error
	switch operation {
	case SetOperation, RemoveOperation:
		// names and tags allowed
		if !ec.Tags.Has(token) && !ec.Names.Has(token) {
			err = newErrInvalidExpression(exp, operation, ErrUnknownNameOrTag)
		}
	case AddOperation:
		// only names are allowed
		if !ec.Names.Has(token) {
			if ec.Tags.Has(token) {
				err = newErrInvalidExpression(exp, operation, ErrTagsNotAllowed)
			} else {
				err = newErrInvalidExpression(exp, operation, ErrUnknownNameOrTag)
			}
		}
	case SubSelectOperation:
		if token == "all" {
			// special case: we cannot sub-select all (this is most likely a misconfiguration and the user intended to use the set operation)
			err = newErrInvalidExpression(exp, operation, ErrAllNotAllowed)
		} else if !ec.Tags.Has(token) {
			// only tags are allowed...
			if ec.Names.Has(token) {
				err = newErrInvalidExpression(exp, operation, ErrNamesNotAllowed)
			} else {
				err = newErrInvalidExpression(exp, operation, ErrUnknownNameOrTag)
			}
		}
	}

	var errs []error
	if err != nil {
		errs = append(errs, err)
	}

	return Expression{
		Operation: operation,
		Operand:   token,
		Errors:    errs,
	}
}

func newExpressionsFromSelectionRequest(nc *expressionContext, selectionRequest cataloging.SelectionRequest) Expressions {
	var all Expressions

	for _, exp := range selectionRequest.DefaultNamesOrTags {
		all = append(all, nc.newExpression(exp, SetOperation, exp))
	}

	for _, exp := range selectionRequest.SubSelectTags {
		all = append(all, nc.newExpression(exp, SubSelectOperation, exp))
	}

	for _, exp := range selectionRequest.AddNames {
		all = append(all, nc.newExpression(exp, AddOperation, exp))
	}

	for _, exp := range selectionRequest.RemoveNamesOrTags {
		all = append(all, nc.newExpression(exp, RemoveOperation, exp))
	}

	sort.Sort(all)
	return all
}

func isValidNode(s string) bool {
	return expressionNodePattern.Match([]byte(s))
}

func (e Expressions) Clone() Expressions {
	clone := make(Expressions, len(e))
	copy(clone, e)
	return clone
}

func (e Expression) String() string {
	var op string
	switch e.Operation {
	case AddOperation:
		op = "+"
	case RemoveOperation:
		op = "-"
	case SubSelectOperation:
		op = ""
	case SetOperation:
		op = ""
	default:
		op = "?"
	}
	return op + e.Operand
}

func (e Expressions) Len() int {
	return len(e)
}

func (e Expressions) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// order of operations
var orderOfOps = map[Operation]int{
	SetOperation:       1,
	SubSelectOperation: 2,
	RemoveOperation:    3,
	AddOperation:       4,
}

func (e Expressions) Less(i, j int) bool {
	ooi := orderOfOps[e[i].Operation]
	ooj := orderOfOps[e[j].Operation]

	if ooi != ooj {
		return ooi < ooj
	}

	return i < j
}

func (e Expressions) Errors() (errs []error) {
	for _, n := range e {
		if len(n.Errors) > 0 {
			errs = append(errs, n.Errors...)
		}
	}
	return errs
}

func (e Expressions) Validate() error {
	errs := e.Errors()
	if len(errs) == 0 {
		return nil
	}
	var err error
	return multierror.Append(err, e.Errors()...)
}
