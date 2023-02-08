package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogicalStrings(t *testing.T) {
	tests := []struct {
		elm      LogicalStrings
		expected string
	}{
		{LogicalStrings{Simple: []string{"a"}}, "a"},
		{LogicalStrings{Simple: []string{"a", "b"}}, "a AND b"},
		{LogicalStrings{Simple: []string{"a", "b"}, Joiner: AND}, "a AND b"},
		{LogicalStrings{Simple: []string{"a", "b", "c"}, Joiner: OR}, "a OR b OR c"},
		{LogicalStrings{
			Compound: []LogicalStrings{
				{Simple: []string{"a", "b"}, Joiner: OR},
				{Simple: []string{"c", "d"}, Joiner: OR},
			},
			Joiner: AND,
		}, "(a OR b) AND (c OR d)"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			assert.Equal(t, test.expected, test.elm.String())
		})
	}
}

func TestParseLogicalStrings(t *testing.T) {
	tests := []struct {
		input    string
		expected LogicalStrings
	}{
		{"a", LogicalStrings{Simple: []string{"a"}}},
		{"a AND b", LogicalStrings{Simple: []string{"a", "b"}, Joiner: AND}},
		{"a OR b", LogicalStrings{Simple: []string{"a", "b"}, Joiner: OR}},
		{"a AND (b OR c)", LogicalStrings{Simple: []string{"a"}, Joiner: AND, Compound: []LogicalStrings{
			{Simple: []string{"b", "c"}, Joiner: OR},
		}}},
		{"(a AND b) OR (c AND d)", LogicalStrings{Joiner: OR, Compound: []LogicalStrings{
			{Simple: []string{"a", "b"}, Joiner: AND},
			{Simple: []string{"c", "d"}, Joiner: AND},
		}}},
		{"(a AND b) OR (c AND (d OR e))", LogicalStrings{Joiner: OR, Compound: []LogicalStrings{
			{Simple: []string{"a", "b"}, Joiner: AND},
			{Simple: []string{"c"}, Compound: []LogicalStrings{
				{Simple: []string{"d", "e"}, Joiner: OR},
			}, Joiner: AND},
		}}},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual, err := ParseLogicalStrings(test.input)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
