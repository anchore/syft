package file

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestContentsCataloger(t *testing.T) {
	allFiles := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}

	tests := []struct {
		name     string
		globs    []string
		maxSize  int64
		files    []string
		expected map[source.Coordinates]string
	}{
		{
			name:  "multi-pattern",
			globs: []string{"test-fixtures/last/*.txt", "test-fixtures/*.txt"},
			files: allFiles,
			expected: map[source.Coordinates]string{
				source.NewLocation("test-fixtures/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:     "no-patterns",
			globs:    []string{},
			files:    []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"},
			expected: map[source.Coordinates]string{},
		},
		{
			name:  "all-txt",
			globs: []string{"**/*.txt"},
			files: allFiles,
			expected: map[source.Coordinates]string{
				source.NewLocation("test-fixtures/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:  "subpath",
			globs: []string{"test-fixtures/*.txt"},
			files: allFiles,
			expected: map[source.Coordinates]string{
				source.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:    "size-filter",
			maxSize: 42,
			globs:   []string{"**/*.txt"},
			files:   allFiles,
			expected: map[source.Coordinates]string{
				source.NewLocation("test-fixtures/last/path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := NewContentsCataloger(test.globs, test.maxSize)
			assert.NoError(t, err)

			resolver := source.NewMockResolverForPaths(test.files...)
			actual, err := c.Catalog(resolver)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual, "mismatched contents")

		})
	}
}
