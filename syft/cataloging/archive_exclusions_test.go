package cataloging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ArchiveExclusionPatterns(t *testing.T) {
	// the pattern's own shape is the whole rule, so every accepted shape is stated here rather than
	// only the two obvious ones. `*/x` is the interesting one: it names a definite depth measured
	// from the scan root, so it describes a layout that exists only there and is anchored, exactly
	// like `./x`. Only `**/x` means the same thing wherever it is rooted, which is what makes
	// re-rooting it at an extraction directory a reading of it rather than a coincidence.
	tests := []struct {
		name       string
		exclusions []string
		want       []string
	}{
		{
			name:       "nothing configured",
			exclusions: nil,
			want:       nil,
		},
		{
			name:       "root-anchored does not reach inside",
			exclusions: []string{"./nested/marker.txt"},
			want:       nil,
		},
		{
			name:       "one-level-down is anchored too and does not reach inside",
			exclusions: []string{"*/vendor"},
			want:       nil,
		},
		{
			name:       "any-depth reaches inside",
			exclusions: []string{"**/*.rpm"},
			want:       []string{"**/*.rpm"},
		},
		{
			name:       "mixed keeps only the any-depth ones, in order",
			exclusions: []string{"./a", "**/b", "*/c", "**/d"},
			want:       []string{"**/b", "**/d"},
		},
		{
			name: "a trailing slash is trimmed",
			// it reads as "a directory" but doublestar.Match discards it, so a pattern keeping it
			// matches nothing at all (issue #4839)
			exclusions: []string{"**/vendor/"},
			want:       []string{"**/vendor"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ArchiveExclusionPatterns(tt.exclusions))
		})
	}
}
