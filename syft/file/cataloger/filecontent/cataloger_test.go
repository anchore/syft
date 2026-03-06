package filecontent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

func TestContentsCataloger(t *testing.T) {
	allFiles := []string{"testdata/last/path.txt", "testdata/another-path.txt", "testdata/a-path.txt"}

	tests := []struct {
		name     string
		globs    []string
		maxSize  int64
		files    []string
		expected map[file.Coordinates]string
	}{
		{
			name:  "multi-pattern",
			globs: []string{"testdata/last/*.txt", "testdata/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("testdata/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:     "no-patterns",
			globs:    []string{},
			files:    []string{"testdata/last/path.txt", "testdata/another-path.txt", "testdata/a-path.txt"},
			expected: map[file.Coordinates]string{},
		},
		{
			name:  "all-txt",
			globs: []string{"**/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("testdata/last/path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:  "subpath",
			globs: []string{"testdata/*.txt"},
			files: allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("testdata/another-path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/a-path.txt").Coordinates:       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:    "size-filter",
			maxSize: 42,
			globs:   []string{"**/*.txt"},
			files:   allFiles,
			expected: map[file.Coordinates]string{
				file.NewLocation("testdata/last/path.txt").Coordinates: "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				file.NewLocation("testdata/a-path.txt").Coordinates:    "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
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
