package unknown

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_visitErrors(t *testing.T) {
	tests := []struct {
		name      string
		in        error
		transform func(error) error
		expected  string
	}{
		{
			name: "return",
			in:   fmt.Errorf("err1"),
			transform: func(e error) error {
				return e
			},
			expected: "err1",
		},
		{
			name: "omit",
			in:   fmt.Errorf("err1"),
			transform: func(_ error) error {
				return nil
			},
			expected: "<nil>",
		},
		{
			name: "wrapped return",
			in:   fmt.Errorf("wrapped: %w", fmt.Errorf("err1")),
			transform: func(e error) error {
				return e
			},
			expected: "wrapped: err1",
		},
		{
			name: "wrapped omit",
			in:   fmt.Errorf("wrapped: %w", fmt.Errorf("err1")),
			transform: func(e error) error {
				if e.Error() == "err1" {
					return nil
				}
				return e
			},
			expected: "<nil>",
		},
		{
			name: "joined return",
			in:   errors.Join(fmt.Errorf("err1"), fmt.Errorf("err2")),
			transform: func(e error) error {
				return e
			},
			expected: "err1\nerr2",
		},
		{
			name: "joined omit",
			in:   errors.Join(fmt.Errorf("err1"), fmt.Errorf("err2")),
			transform: func(_ error) error {
				return nil
			},
			expected: "<nil>",
		},
		{
			name: "joined omit first",
			in:   errors.Join(fmt.Errorf("err1"), fmt.Errorf("err2")),
			transform: func(e error) error {
				if e.Error() == "err1" {
					return nil
				}
				return e
			},
			expected: "err2",
		},
		{
			name: "joined wrapped return",
			in:   errors.Join(fmt.Errorf("wrapped: %w", fmt.Errorf("err1")), fmt.Errorf("err2")),
			transform: func(e error) error {
				return e
			},
			expected: "wrapped: err1\nerr2",
		},
		{
			name: "joined wrapped omit first",
			in:   errors.Join(fmt.Errorf("wrapped: %w", fmt.Errorf("err1")), fmt.Errorf("err2")),
			transform: func(e error) error {
				if e.Error() == "err1" {
					return nil
				}
				return e
			},
			expected: "err2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := visitErrors(test.in, test.transform)
			got := fmt.Sprintf("%v", gotErr)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_Join(t *testing.T) {
	err1 := fmt.Errorf("err1")
	err2 := fmt.Errorf("err2")

	tests := []struct {
		name     string ``
		in       []error
		expected string
	}{
		{
			name:     "basic",
			in:       []error{fmt.Errorf("err")},
			expected: "err",
		},
		{
			name:     "wrapped",
			in:       []error{fmt.Errorf("outer: %w", fmt.Errorf("err"))},
			expected: "outer: err",
		},
		{
			name:     "wrapped joined",
			in:       []error{errors.Join(fmt.Errorf("outer: %w", fmt.Errorf("err1")), fmt.Errorf("err2"))},
			expected: "outer: err1\nerr2",
		},
		{
			name:     "duplicates",
			in:       []error{err1, err1, err2},
			expected: "err1\nerr2",
		},
		{
			name:     "nested duplicates",
			in:       []error{errors.Join(err1, err2), err1, err2},
			expected: "err1\nerr2",
		},
		{
			name:     "nested duplicates coords",
			in:       []error{New(file.NewLocation("l1"), errors.Join(fmt.Errorf("err1"), fmt.Errorf("err2"))), fmt.Errorf("err1"), fmt.Errorf("err2")},
			expected: "l1: err1\nl1: err2\nerr1\nerr2",
		},
		{
			name:     "all nil",
			in:       []error{nil, nil, nil},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Join(test.in...)
			if test.expected == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, test.expected, got.Error())
		})
	}
}

func Test_flatten(t *testing.T) {
	coords := file.Coordinates{
		RealPath: "real/path",
	}
	e1 := fmt.Errorf("e1")
	e2 := fmt.Errorf("e2")
	c1 := New(coords, fmt.Errorf("c1"))
	c2 := New(coords, fmt.Errorf("c2"))
	tests := []struct {
		name     string ``
		in       error
		expected string
	}{
		{
			name:     "basic",
			in:       errors.Join(e1, e2),
			expected: "e1//e2",
		},
		{
			name:     "coords",
			in:       New(coords, e1),
			expected: "real/path: e1",
		},
		{
			name:     "coords with joined children",
			in:       New(coords, errors.Join(e1, e2)),
			expected: "real/path: e1//real/path: e2",
		},
		{
			name:     "very nested",
			in:       errors.Join(errors.Join(errors.Join(errors.Join(e1, c1), e2), c2), e2),
			expected: "e1//real/path: c1//e2//real/path: c2//e2",
		},
	}
	toString := func(errs ...error) string {
		var parts []string
		for _, e := range errs {
			parts = append(parts, e.Error())
		}
		return strings.Join(parts, "//")
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := flatten(test.in)
			require.NotNil(t, got)
			require.Equal(t, test.expected, toString(got...))
		})
	}
}

func Test_Append(t *testing.T) {
	e1 := New(file.NewLocation("l1"), fmt.Errorf("e1"))
	e2 := Append(e1, file.NewLocation("l2"), fmt.Errorf("e2"))
	e3 := Appendf(e2, file.NewLocation("l3"), "%s", "e3")
	require.Equal(t, "l1: e1\nl2: e2\nl3: e3", e3.Error())

	e1 = New(file.NewLocation("l1"), nil)
	require.Nil(t, e1)
	e2 = Append(e1, file.NewLocation("l2"), fmt.Errorf("e2"))
	e3 = Appendf(e2, file.NewLocation("l3"), "%s", "e3")
	require.Equal(t, "l2: e2\nl3: e3", e3.Error())

	e1 = New(file.NewLocation("l1"), fmt.Errorf("e1"))
	e2 = Append(e1, file.NewLocation("l2"), nil)
	e3 = Appendf(e2, file.NewLocation("l3"), "%s", "e3")
	require.Equal(t, "l1: e1\nl3: e3", e3.Error())
}
