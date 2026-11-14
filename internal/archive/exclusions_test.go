package archive

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewExclusions(t *testing.T) {
	tests := []struct {
		name  string
		given []string
		want  Exclusions
	}{
		{name: "nothing configured"},
		{name: "root-anchored does not reach inside", given: []string{"./nested/marker.txt"}},
		{name: "one level down is anchored too", given: []string{"*/vendor"}},
		{name: "any depth reaches inside", given: []string{"**/*.rpm"}, want: Exclusions{"**/*.rpm"}},
		{name: "mixed keeps only the any-depth patterns", given: []string{"./a", "**/b", "*/c", "**/d"}, want: Exclusions{"**/b", "**/d"}},
		// a trailing slash makes doublestar match nothing (issue #4839)
		{name: "a trailing slash is trimmed", given: []string{"**/vendor/"}, want: Exclusions{"**/vendor"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewExclusions(tt.given))
		})
	}
}

func TestExclusions_Excludes(t *testing.T) {
	exclusions := NewExclusions([]string{"**/vendor", "**/*.rpm"})

	tests := []struct {
		path string
		want bool
	}{
		{"vendor", true},
		{"a/vendor", true},
		{"vendor/x/y.go", true},
		{"a/vendor/y.go", true},
		{"pkg.rpm", true},
		{"deep/down/pkg.rpm", true},
		{"keep/vendored.txt", false},
		{"vendor-ish", false},
		{"keep.txt", false},
		{"PKG.RPM", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, exclusions.Excludes(tt.path))
		})
	}

	assert.False(t, NewExclusions(nil).Excludes("anything"))
	assert.False(t, Exclusions{"["}.Excludes("keep.txt"), "a malformed pattern excludes nothing")
}
