package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func must(c CPE, e error) CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestNewCPE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CPE
	}{
		{
			name:     "gocase",
			input:    `cpe:/a:10web:form_maker:1.0.0::~~~wordpress~~`,
			expected: must(NewCPE(`cpe:2.3:a:10web:form_maker:1.0.0:*:*:*:*:wordpress:*:*`)),
		},
		{
			name:     "dashes",
			input:    `cpe:/a:7-zip:7-zip:4.56:beta:~~~windows~~`,
			expected: must(NewCPE(`cpe:2.3:a:7-zip:7-zip:4.56:beta:*:*:*:windows:*:*`)),
		},
		{
			name:     "URL escape characters",
			input:    `cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~`,
			expected: must(NewCPE(`cpe:2.3:a:$0.99_kindle_books_project:$0.99_kindle_books:6:*:*:*:*:android:*:*`)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewCPE(test.input)
			if err != nil {
				t.Fatalf("got an error while creating CPE: %+v", err)
			}

			if actual.BindToFmtString() != test.expected.BindToFmtString() {
				t.Errorf("mismatched entries:\n\texpected:%+v\n\t  actual:%+v\n", test.expected.BindToFmtString(), actual.BindToFmtString())
			}

		})
	}
}

func Test_normalizeCpeField(t *testing.T) {

	tests := []struct {
		field    string
		expected string
	}{
		{
			field:    "something",
			expected: "something",
		},
		{
			field:    "some\\thing",
			expected: `some\thing`,
		},
		{
			field:    "*",
			expected: "",
		},
		{
			field:    "",
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			assert.Equal(t, test.expected, normalizeCpeField(test.field))
		})
	}
}
