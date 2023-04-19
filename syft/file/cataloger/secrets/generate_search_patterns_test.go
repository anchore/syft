package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSearchPatterns(t *testing.T) {
	tests := []struct {
		name       string
		base       map[string]string
		additional map[string]string
		exclude    []string
		expected   map[string]string
	}{
		{
			name: "use-base-set",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			expected: map[string]string{
				"in-default": `(?m)^secret_key=.*`,
			},
		},
		{
			name: "exclude-from-base-set",
			base: map[string]string{
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude: []string{"also-in-default"},
			expected: map[string]string{
				"in-default": `(?m)^secret_key=.*`,
			},
		},
		{
			name: "exclude-multiple-from-base-set",
			base: map[string]string{
				"in-default":             `^secret_key=.*`,
				"also-in-default":        `^also-in-default=.*`,
				"furthermore-in-default": `^furthermore-in-default=.*`,
			},
			exclude: []string{"also-in-default", "furthermore-in-default"},
			expected: map[string]string{
				"in-default": `(?m)^secret_key=.*`,
			},
		},
		{
			name: "exclude-all",
			base: map[string]string{
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude:  []string{"*"},
			expected: map[string]string{},
		},
		{
			name: "exclude-some",
			base: map[string]string{
				"real":            `^real=.*`,
				"in-default":      `^secret_key=.*`,
				"also-in-default": `^also-in-default=.*`,
			},
			exclude: []string{"*-default"},
			expected: map[string]string{
				"real": `(?m)^real=.*`,
			},
		},
		{
			name: "additional-pattern-unison",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			additional: map[string]string{
				"additional": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `(?m)^secret_key=.*`,
				"additional": `(?m)^additional=.*`,
			},
		},
		{
			name: "override",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			additional: map[string]string{
				"in-default": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `(?m)^additional=.*`,
			},
		},
		{
			name: "exclude-and-override",
			base: map[string]string{
				"in-default": `^secret_key=.*`,
			},
			exclude: []string{"in-default"},
			additional: map[string]string{
				"in-default": `^additional=.*`,
			},
			expected: map[string]string{
				"in-default": `(?m)^additional=.*`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualObj, err := GenerateSearchPatterns(test.base, test.additional, test.exclude)
			if err != nil {
				t.Fatalf("unable to combine: %+v", err)
			}

			actual := make(map[string]string)
			for n, v := range actualObj {
				actual[n] = v.String()
			}

			assert.Equal(t, test.expected, actual, "mismatched combination")
		})
	}
}
