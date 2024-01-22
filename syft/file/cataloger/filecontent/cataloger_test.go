package filecontent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

func TestContentsCataloger(t *testing.T) {
	allFiles := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}

	tests := []struct {
		name     string
		globs    []string
		maxSize  int64
		files    []string
		expected map[file.Coordinates]string
	}{
		{
			name:  "multi-pattern",
			globs: []string{"test-fixtures/last/*.txt", "test-fixtures/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("test-fixtures/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:     "no-patterns",
			globs:    []string{},
			files:    []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"},
			expected: map[file.Coordinates]string{},
		},
		{
			name:  "all-txt",
			globs: []string{"**/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("test-fixtures/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:  "subpath",
			globs: []string{"test-fixtures/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("test-fixtures/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:    "size-filter",
			maxSize: 42,
			globs:   []string{"**/*.txt"},
			files:   allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("test-fixtures/last/path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("test-fixtures/a-path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCataloger(Config{
				Globs:              test.globs,
				SkipFilesAboveSize: test.maxSize,
			})

			resolver := file.NewMockResolverForPaths(test.files...)
			actual, err := c.Catalog(context.Background(), resolver)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual, "mismatched contents")

		})
	}
}
