package homebrew

import (
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		packageVersion string
		expected       string
	}{
		{
			name:           "standard homebrew package URL",
			packageName:    "foo",
			packageVersion: "1.2.3",
			expected:       "pkg:homebrew/foo@1.2.3",
		},
		{
			name:           "another example",
			packageName:    "bar",
			packageVersion: "9.8.7",
			expected:       "pkg:homebrew/bar@9.8.7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.packageName, test.packageVersion)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
