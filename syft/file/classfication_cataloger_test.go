package file

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestClassifierCataloger_DefaultClassifiers_PositiveCases(t *testing.T) {
	tests := []struct {
		name           string
		fixtureDir     string
		location       string
		expected       []Classification
		constructorErr bool
		catalogErr     bool
	}{
		{
			name:       "positive-libpython3.7.so",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/libpython3.7.so",
			expected: []Classification{
				{
					Class: "python-binary",
					Metadata: map[string]string{
						"version": "3.7.4a-vZ9",
					},
				},
			},
		},
		{
			name:       "positive-python3.6",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/python3.6",
			expected: []Classification{
				{
					Class: "python-binary",
					Metadata: map[string]string{
						"version": "3.6.3a-vZ9",
					},
				},
			},
		},
		{
			name:       "positive-patchlevel.h",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/patchlevel.h",
			expected: []Classification{
				{
					Class: "cpython-source",
					Metadata: map[string]string{
						"version": "3.9-aZ5",
					},
				},
			},
		},
		{
			name:       "positive-go",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/go",
			expected: []Classification{
				{
					Class: "go-binary",
					Metadata: map[string]string{
						"version": "1.14",
					},
				},
			},
		},
		{
			name:       "positive-go-hint",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/VERSION",
			expected: []Classification{
				{
					Class: "go-binary-hint",
					Metadata: map[string]string{
						"version": "1.15",
					},
				},
			},
		},
		{
			name:       "positive-busybox",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "test-fixtures/classifiers/positive/busybox",
			expected: []Classification{
				{
					Class: "busybox-binary",
					Metadata: map[string]string{
						"version": "3.33.3",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			c, err := NewClassificationCataloger(DefaultClassifiers)
			if err != nil && !test.constructorErr {
				t.Fatalf("could not create cataloger (but should have been able to): %+v", err)
			} else if err == nil && test.constructorErr {
				t.Fatalf("expected constructor error but did not get one")
			} else if test.constructorErr && err != nil {
				return
			}

			src, err := source.NewFromDirectory(test.fixtureDir)
			if err != nil {
				t.Fatalf("could not create source: %+v", err)
			}

			resolver, err := src.FileResolver(source.SquashedScope)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			actualResults, err := c.Catalog(resolver)
			if err != nil && !test.catalogErr {
				t.Fatalf("could not catalog (but should have been able to): %+v", err)
			} else if err == nil && test.catalogErr {
				t.Fatalf("expected catalog error but did not get one")
			} else if test.catalogErr && err != nil {
				return
			}

			loc := source.NewLocation(test.location)

			if _, ok := actualResults[loc]; !ok {
				t.Fatalf("could not find test location=%q", test.location)
			}

			assert.Equal(t, test.expected, actualResults[loc])
		})
	}
}

func TestClassifierCataloger_DefaultClassifiers_NegativeCases(t *testing.T) {

	c, err := NewClassificationCataloger(DefaultClassifiers)
	if err != nil {
		t.Fatalf("could not create cataloger: %+v", err)
	}

	src, err := source.NewFromDirectory("test-fixtures/classifiers/negative")
	if err != nil {
		t.Fatalf("could not create source: %+v", err)
	}

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("could not create resolver: %+v", err)
	}

	actualResults, err := c.Catalog(resolver)
	if err != nil {
		t.Fatalf("could not catalog: %+v", err)
	}
	assert.Equal(t, 0, len(actualResults))

}
