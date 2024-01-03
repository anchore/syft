package task

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

func Test_newExpressionsFromSelectionRequest(t *testing.T) {
	ts := []Task{
		dummyTask("1", "t1"),
		dummyTask("2", "t2"),
		dummyTask("3", "t3"),
		dummyTask("4", "t4"),
		dummyTask("5"),
		dummyTask("6"),
	}

	nc := newExpressionContext(ts)

	var tests = []struct {
		name           string
		basis          []string
		expressions    []string
		expected       Expressions
		expectedErrors []error
	}{
		{
			name:        "empty input",
			basis:       []string{},
			expressions: []string{},
			expected:    nil,
		},
		{
			name:        "valid single set operation",
			basis:       []string{"1"},
			expressions: []string{},
			expected: []Expression{
				{Operation: SetOperation, Operand: "1"},
			},
		},
		{
			name:        "add operation",
			basis:       []string{},
			expressions: []string{"+4"},
			expected: []Expression{
				{Operation: AddOperation, Operand: "4"},
			},
		},
		{
			name:        "remove operation",
			basis:       []string{},
			expressions: []string{"-3"},
			expected: []Expression{
				{Operation: RemoveOperation, Operand: "3"},
			},
		},
		{
			name:        "select operation",
			basis:       []string{},
			expressions: []string{"t2"},
			expected: []Expression{
				{Operation: SubSelectOperation, Operand: "t2"},
			},
		},
		{
			name:        "mixed operations order",
			basis:       []string{"1"},
			expressions: []string{"+4", "-3", "t2"},
			expected: []Expression{
				// note they are sorted by operation
				{Operation: SetOperation, Operand: "1"},
				{Operation: SubSelectOperation, Operand: "t2"},
				{Operation: RemoveOperation, Operand: "3"},
				{Operation: AddOperation, Operand: "4"},
			},
		},
		{
			name:           "invalid token",
			basis:          []string{"!1"},
			expressions:    []string{},
			expected:       nil,
			expectedErrors: []error{ErrInvalidToken},
		},
		{
			name:           "use + operator in basis",
			basis:          []string{"+1"},
			expressions:    []string{},
			expected:       nil,
			expectedErrors: []error{ErrInvalidToken},
		},
		{
			name:           "use - operator in basis",
			basis:          []string{"-1"},
			expressions:    []string{},
			expected:       nil,
			expectedErrors: []error{ErrInvalidToken},
		},
		{
			name:           "invalid name",
			basis:          []string{},
			expressions:    []string{"+t1"},
			expected:       nil,
			expectedErrors: []error{ErrTagsNotAllowed},
		},
		{
			name:           "invalid tag",
			basis:          []string{},
			expressions:    []string{"1"},
			expected:       nil,
			expectedErrors: []error{ErrNamesNotAllowed},
		},
		{
			name:           "invalid use of all",
			basis:          []string{},
			expressions:    []string{"all"},
			expected:       nil,
			expectedErrors: []error{ErrAllNotAllowed},
		},
		{
			name:        "allow all operand",
			basis:       []string{"all"},
			expressions: []string{},
			expected: []Expression{
				// note they are sorted by operation
				{Operation: SetOperation, Operand: "all"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req := pkgcataloging.NewSelectionRequest().WithDefaults(tt.basis...).WithExpression(tt.expressions...)

			result := newExpressionsFromSelectionRequest(nc, req)
			if tt.expectedErrors != nil {
				errs := result.Errors()
				require.Len(t, errs, len(tt.expectedErrors))
				for i, err := range tt.expectedErrors {
					var target ErrInvalidExpression
					require.ErrorAs(t, errs[i], &target)
					assert.Equal(t, err, target.Err)
				}
			} else {
				assert.Empty(t, result.Errors())
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func Test_expressionNodes_sort(t *testing.T) {
	tests := []struct {
		name    string
		subject Expressions
		want    Expressions
	}{
		{
			name: "sort operations but keep token order",
			subject: []Expression{
				{
					Operation: AddOperation,
					Operand:   "8",
				},
				{
					Operation: AddOperation,
					Operand:   "7",
				},
				{
					Operation: RemoveOperation,
					Operand:   "6",
				},
				{
					Operation: RemoveOperation,
					Operand:   "5",
				},
				{
					Operation: SetOperation,
					Operand:   "2",
				},
				{
					Operation: SetOperation,
					Operand:   "1",
				},
				{
					Operation: SubSelectOperation,
					Operand:   "4",
				},
				{
					Operation: SubSelectOperation,
					Operand:   "3",
				},
			},
			want: []Expression{
				{
					Operation: SetOperation,
					Operand:   "2",
				},
				{
					Operation: SetOperation,
					Operand:   "1",
				},
				{
					Operation: SubSelectOperation,
					Operand:   "4",
				},
				{
					Operation: SubSelectOperation,
					Operand:   "3",
				},
				{
					Operation: RemoveOperation,
					Operand:   "6",
				},
				{
					Operation: RemoveOperation,
					Operand:   "5",
				},
				{
					Operation: AddOperation,
					Operand:   "8",
				},
				{
					Operation: AddOperation,
					Operand:   "7",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.subject.Clone()
			sort.Sort(s)
			assert.Equal(t, tt.want, s)
		})
	}
}
