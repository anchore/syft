package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_normalizeName(t *testing.T) {
	tests := []struct {
		input   string
		expects string
	}{
		{
			// note: extra spaces
			input:   "  Alex Goodman  ",
			expects: "alexgoodman",
		},
		{
			input:   "Alex Goodman, LLC",
			expects: "alexgoodman",
		},
		{
			input:   "alex.goodman",
			expects: "alex.goodman",
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expects, normalizeName(test.input))
		})
	}
}

func Test_normalizePersonName(t *testing.T) {
	tests := []struct {
		input   string
		expects string
	}{
		{
			// note: extra spaces
			input:   "  Alex Goodman  ",
			expects: "alex_goodman",
		},
		{
			input:   "Alex Goodman",
			expects: "alex_goodman",
		},
		{
			input:   "Alex.Goodman",
			expects: "alex_goodman",
		},
		{
			input:   "Alex.Goodman",
			expects: "alex_goodman",
		},
		{
			input:   "AlexGoodman",
			expects: "alexgoodman",
		},
		{
			input:   "The Apache Software Foundation",
			expects: "apache_software_foundation",
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expects, normalizePersonName(test.input))
		})
	}
}
