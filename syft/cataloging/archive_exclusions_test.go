package cataloging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ArchiveExclusionPatterns(t *testing.T) {
	// the pattern's shape is the whole rule, so every accepted shape is listed. `*/x` names a definite
	// depth from the scan root, anchoring it there exactly as `./x` is; only `**/x` means the same thing
	// wherever it is rooted.
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
			// matches nothing (issue #4839)
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
