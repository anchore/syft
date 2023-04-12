package php

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		metadata parsedData
		expected string
	}{
		{
			name: "with extractable vendor",
			metadata: parsedData{
				[]string{},
				pkg.PhpComposerJSONMetadata{
					Version: "1.0.1",
					Name:    "ven/name",
				},
			},
			expected: "pkg:composer/ven/name@1.0.1",
		},
		{
			name: "name with slashes (invalid)",
			metadata: parsedData{
				[]string{},
				pkg.PhpComposerJSONMetadata{
					Name:    "ven/name/component",
					Version: "1.0.1",
				},
			},
			expected: "pkg:composer/ven/name-component@1.0.1",
		},
		{
			name: "unknown vendor",
			metadata: parsedData{
				[]string{},
				pkg.PhpComposerJSONMetadata{
					Name:    "name",
					Version: "1.0.1",
				},
			},
			expected: "pkg:composer/name@1.0.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.metadata)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
