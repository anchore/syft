package file

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestContentsCataloger(t *testing.T) {
	allFiles := []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"}

	tests := []struct {
		name       string
		globs      []string
		maxSize    int64
		files      []string
		expected   map[source.Location]string
		catalogErr bool
	}{
		{
			name:  "multi-pattern",
			globs: []string{"test-fixtures/last/*.txt", "test-fixtures/*.txt"},
			files: allFiles,
			expected: map[source.Location]string{
				source.NewLocation("test-fixtures/last/path.txt"):    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/another-path.txt"): "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt"):       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:     "no-patterns",
			globs:    []string{},
			files:    []string{"test-fixtures/last/path.txt", "test-fixtures/another-path.txt", "test-fixtures/a-path.txt"},
			expected: map[source.Location]string{},
		},
		{
			name:  "all-txt",
			globs: []string{"**/*.txt"},
			files: allFiles,
			expected: map[source.Location]string{
				source.NewLocation("test-fixtures/last/path.txt"):    "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/another-path.txt"): "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt"):       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:  "subpath",
			globs: []string{"test-fixtures/*.txt"},
			files: allFiles,
			expected: map[source.Location]string{
				source.NewLocation("test-fixtures/another-path.txt"): "dGVzdC1maXh0dXJlcy9hbm90aGVyLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt"):       "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
		{
			name:    "size-filter",
			maxSize: 42,
			globs:   []string{"**/*.txt"},
			files:   allFiles,
			expected: map[source.Location]string{
				source.NewLocation("test-fixtures/last/path.txt"): "dGVzdC1maXh0dXJlcy9sYXN0L3BhdGgudHh0IGZpbGUgY29udGVudHMh",
				source.NewLocation("test-fixtures/a-path.txt"):    "dGVzdC1maXh0dXJlcy9hLXBhdGgudHh0IGZpbGUgY29udGVudHMh",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := NewContentsCataloger(test.globs, test.maxSize)
			if err != nil {
				t.Fatalf("could not create cataloger: %+v", err)
			}

			resolver := source.NewMockResolverForPaths(test.files...)
			actual, err := c.Catalog(resolver)
			if err != nil && !test.catalogErr {
				t.Fatalf("could not catalog (but should have been able to): %+v", err)
			} else if err == nil && test.catalogErr {
				t.Fatalf("expected catalog error but did not get one")
			} else if test.catalogErr && err != nil {
				return
			}

			assert.Equal(t, test.expected, actual, "mismatched contents")

		})
	}
}
