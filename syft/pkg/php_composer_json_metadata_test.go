package pkg

import (
	"github.com/anchore/syft/syft/linux"
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
)

func TestPhpComposerJsonMetadata_pURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata PhpComposerJSONMetadata
		expected string
	}{
		{
			name: "with extractable vendor",
			metadata: PhpComposerJSONMetadata{
				Name:    "ven/name",
				Version: "1.0.1",
			},
			expected: "pkg:composer/ven/name@1.0.1",
		},
		{
			name: "name with slashes (invalid)",
			metadata: PhpComposerJSONMetadata{
				Name:    "ven/name/component",
				Version: "1.0.1",
			},
			expected: "pkg:composer/ven/name-component@1.0.1",
		},
		{
			name: "unknown vendor",
			metadata: PhpComposerJSONMetadata{
				Name:    "name",
				Version: "1.0.1",
			},
			expected: "pkg:composer/name@1.0.1",
		},
		{
			name: "ignores distro",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: PhpComposerJSONMetadata{
				Name:    "ven/name",
				Version: "1.0.1",
			},
			expected: "pkg:composer/ven/name@1.0.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.metadata.PackageURL(test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
