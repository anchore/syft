package commands

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/task"
)

func Test_filterExpressionErrors_expressionErrorsHelp(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantExpErrs []task.ErrInvalidExpression
		wantErr     assert.ErrorAssertionFunc
		wantHelp    string
	}{
		{
			name:        "no errors",
			err:         nil,
			wantExpErrs: nil,
			wantErr:     assert.NoError,
			wantHelp:    "",
		},
		{
			name: "single non-expression error is retained",
			err:  errors.New("foo"),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Equal(t, "foo", err.Error())
			},
			wantHelp: "",
		},
		{
			name: "multiple non-expression sibling errors are retained",
			err: func() error {
				var err error
				err = multierror.Append(err, errors.New("foo"))
				err = multierror.Append(err, errors.New("bar"))
				return err
			}(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				// note: this is the default formatting from the hashicorp multierror object
				expected := `2 errors occurred:
	* foo
	* bar

`
				return assert.Equal(t, expected, err.Error())
			},
			wantHelp: "",
		},
		{
			name: "has multiple expression errors (with sibling errors)",
			err: func() error {
				var err error
				err = multierror.Append(err, errors.New("foo"))
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed})
				err = multierror.Append(err, errors.New("bar"))
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed})
				err = multierror.Append(err, errors.New("last"))
				return err
			}(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expected := `5 errors occurred:
	* foo
	* invalid expression: "foo": tags are not allowed with this operation (must use exact names)
	* bar
	* invalid expression: "bar": names are not allowed with this operation (must use tags)
	* last

`
				return assert.Equal(t, expected, err.Error())
			},
			wantExpErrs: []task.ErrInvalidExpression{
				{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed},
				{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed},
			},
			wantHelp: `Suggestions:

 ❖ Given expression "--select-catalogers foo"
   However, tags are not allowed with this operation (must use exact names).
   Adding groups of catalogers may result in surprising behavior (create inaccurate SBOMs).
   If you are certain this is what you want to do, use "--override-default-catalogers foo" instead.

 ❖ Given expression "--select-catalogers bar"
   However, names are not allowed with this operation (must use tags).
   It seems like you are intending to add a cataloger in addition to the default set.
   ... Did you mean "--select-catalogers +bar" instead?
`,
		},
		{
			name: "has multiple expression errors (with error chains and sibling errors)",
			err: func() error {
				var err error
				err = multierror.Append(err, fmt.Errorf("foo: %w", fmt.Errorf("bar: %w", errors.New("last"))))
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed})
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed})
				err = multierror.Append(err, errors.New("bottom"))

				return fmt.Errorf("top: %w", fmt.Errorf("middle: %w", err))
			}(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expected := `top: middle: 4 errors occurred:
	* foo: bar: last
	* invalid expression: "foo": tags are not allowed with this operation (must use exact names)
	* invalid expression: "bar": names are not allowed with this operation (must use tags)
	* bottom

`
				return assert.Equal(t, expected, err.Error())
			},
			wantExpErrs: []task.ErrInvalidExpression{
				{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed},
				{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed},
			},
			wantHelp: `Suggestions:

 ❖ Given expression "--select-catalogers foo"
   However, tags are not allowed with this operation (must use exact names).
   Adding groups of catalogers may result in surprising behavior (create inaccurate SBOMs).
   If you are certain this is what you want to do, use "--override-default-catalogers foo" instead.

 ❖ Given expression "--select-catalogers bar"
   However, names are not allowed with this operation (must use tags).
   It seems like you are intending to add a cataloger in addition to the default set.
   ... Did you mean "--select-catalogers +bar" instead?
`,
		},
		{
			name: "has multiple expression errors (with error chains and sibling errors)",
			err: func() error {
				var err error
				err = multierror.Append(err, fmt.Errorf("foo: %w", fmt.Errorf("bar: %w", errors.New("last"))))
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed})
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed})
				err = multierror.Append(err, errors.New("bottom"))

				// note we wrap the top error in a chain
				return fmt.Errorf("top: %w", fmt.Errorf("middle: %w", err))
			}(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expected := `top: middle: 4 errors occurred:
	* foo: bar: last
	* invalid expression: "foo": tags are not allowed with this operation (must use exact names)
	* invalid expression: "bar": names are not allowed with this operation (must use tags)
	* bottom

`
				return assert.Equal(t, expected, err.Error())
			},
			wantExpErrs: []task.ErrInvalidExpression{
				{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed},
				{Expression: "bar", Operation: task.SubSelectOperation, Err: task.ErrNamesNotAllowed},
			},
			wantHelp: `Suggestions:

 ❖ Given expression "--select-catalogers foo"
   However, tags are not allowed with this operation (must use exact names).
   Adding groups of catalogers may result in surprising behavior (create inaccurate SBOMs).
   If you are certain this is what you want to do, use "--override-default-catalogers foo" instead.

 ❖ Given expression "--select-catalogers bar"
   However, names are not allowed with this operation (must use tags).
   It seems like you are intending to add a cataloger in addition to the default set.
   ... Did you mean "--select-catalogers +bar" instead?
`,
		},
		{
			name: "preserve for any errors within ErrInvalidExpression types",
			err: func() error {
				var err error
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed})
				err = multierror.Append(err, task.ErrInvalidExpression{Expression: "bar", Operation: task.SubSelectOperation, Err: errors.New("explanation")}) // this is what makes this test different...

				return err
			}(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				// note: the errors are removed and the help text shows the enriched error help
				expected := `2 errors occurred:
	* invalid expression: "foo": tags are not allowed with this operation (must use exact names)
	* invalid expression: "bar": explanation

`
				return assert.Equal(t, expected, err.Error())
			},
			wantExpErrs: []task.ErrInvalidExpression{
				{Expression: "foo", Operation: task.AddOperation, Err: task.ErrTagsNotAllowed},
				{Expression: "bar", Operation: task.SubSelectOperation, Err: errors.New("explanation")},
			},
			wantHelp: `Suggestions:

 ❖ Given expression "--select-catalogers foo"
   However, tags are not allowed with this operation (must use exact names).
   Adding groups of catalogers may result in surprising behavior (create inaccurate SBOMs).
   If you are certain this is what you want to do, use "--override-default-catalogers foo" instead.

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotExpErrs := filterExpressionErrors(tt.err)
			tt.wantErr(t, tt.err) // ensure the error still remains
			assert.Equal(t, tt.wantExpErrs, gotExpErrs)

			gotHelp := expressionErrorsHelp(gotExpErrs)
			assert.Equal(t, tt.wantHelp, gotHelp)
		})
	}
}

func Test_expressionSuggestions(t *testing.T) {
	tests := []struct {
		name   string
		expErr task.ErrInvalidExpression
		want   string
	}{
		{
			name: "no embedded error",
			expErr: task.ErrInvalidExpression{
				Expression: "example",
			},
			want: ``,
		},
		{
			name: "general error",
			expErr: task.ErrInvalidExpression{
				Err:        errors.New("general error message"),
				Expression: "example",
			},
			want: ``,
		},
		{
			name: "ErrUnknownNameOrTag with add operation",
			expErr: task.ErrInvalidExpression{
				Err:        task.ErrUnknownNameOrTag,
				Operation:  task.AddOperation,
				Expression: "+example",
			},
			want: ``,
		},
		{
			name: "ErrUnknownNameOrTag with subselect operation",
			expErr: task.ErrInvalidExpression{
				Err:        task.ErrUnknownNameOrTag,
				Operation:  task.SubSelectOperation,
				Expression: "example",
			},
			want: ``,
		},
		{
			name: "ErrNamesNotAllowed with subselect operator",
			expErr: task.ErrInvalidExpression{
				Err:        task.ErrNamesNotAllowed,
				Operation:  task.SubSelectOperation,
				Expression: "example",
			},
			want: ` ❖ Given expression "--select-catalogers example"
   However, names are not allowed with this operation (must use tags).
   It seems like you are intending to add a cataloger in addition to the default set.
   ... Did you mean "--select-catalogers +example" instead?
`,
		},
		{
			name: "ErrTagsNotAllowed with add operation",
			expErr: task.ErrInvalidExpression{
				Err:        task.ErrTagsNotAllowed,
				Operation:  task.AddOperation,
				Expression: "+example",
			},
			want: ` ❖ Given expression "--select-catalogers +example"
   However, tags are not allowed with this operation (must use exact names).
   Adding groups of catalogers may result in surprising behavior (create inaccurate SBOMs).
   If you are certain this is what you want to do, use "--override-default-catalogers example" instead.
`,
		},
		{
			name: "ErrAllNotAllowed with subselect operation",
			expErr: task.ErrInvalidExpression{
				Err:        task.ErrAllNotAllowed,
				Operation:  task.SubSelectOperation,
				Expression: "example",
			},
			want: ` ❖ Given expression "--select-catalogers example"
   However, you cannot use the 'all' operand in this context.
   It seems like you are intending to use all catalogers (which is not recommended).
   ... Did you mean "--override-default-catalogers example" instead?
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, expressionSuggetions(tt.expErr))
		})
	}
}
