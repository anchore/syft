package file

import (
	"github.com/anchore/stereoscope/pkg/imagetest"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestClassifierCataloger_DefaultClassifiers_PositiveCases(t *testing.T) {
	tests := []struct {
		name        string
		fixtureDir  string
		location    string
		expected    []Classification
		expectedErr func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			name:       "positive-libpython3.7.so",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "libpython3.7.so",
			expected: []Classification{
				{
					Class: "python-binary",
					Metadata: map[string]string{
						"version": "3.7.4a-vZ9",
					},
				},
			},
			expectedErr: assert.NoError,
		},
		{
			name:       "positive-python3.6",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "python3.6",
			expected: []Classification{
				{
					Class: "python-binary",
					Metadata: map[string]string{
						"version": "3.6.3a-vZ9",
					},
				},
			},
			expectedErr: assert.NoError,
		},
		{
			name:       "positive-patchlevel.h",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "patchlevel.h",
			expected: []Classification{
				{
					Class: "cpython-source",
					Metadata: map[string]string{
						"version": "3.9-aZ5",
					},
				},
			},
			expectedErr: assert.NoError,
		},
		{
			name:       "positive-go",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "go",
			expected: []Classification{
				{
					Class: "go-binary",
					Metadata: map[string]string{
						"version": "1.14",
					},
				},
			},
			expectedErr: assert.NoError,
		},
		{
			name:       "positive-go-hint",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "VERSION",
			expected: []Classification{
				{
					Class: "go-binary-hint",
					Metadata: map[string]string{
						"version": "1.15",
					},
				},
			},
			expectedErr: assert.NoError,
		},
		{
			name:       "positive-busybox",
			fixtureDir: "test-fixtures/classifiers/positive",
			location:   "[", // note: busybox is a link to [
			expected: []Classification{
				{
					Class: "busybox-binary",
					Metadata: map[string]string{
						"version": "3.33.3",
					},
				},
			},
			expectedErr: assert.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			c, err := NewClassificationCataloger(DefaultClassifiers)
			test.expectedErr(t, err)

			src, err := source.NewFromDirectory(test.fixtureDir)
			test.expectedErr(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			test.expectedErr(t, err)

			actualResults, err := c.Catalog(resolver)
			test.expectedErr(t, err)

			ok := false
			for actualLoc, actualClassification := range actualResults {
				if test.location == actualLoc.RealPath {
					ok = true
					assert.Equal(t, test.expected, actualClassification)
				}
			}

			if !ok {
				t.Fatalf("could not find test location=%q", test.location)
			}

		})
	}
}

func TestClassifierCataloger_DefaultClassifiers_PositiveCases_Image(t *testing.T) {
	tests := []struct {
		name         string
		fixtureImage string
		location     string
		expected     []Classification
		expectedErr  func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			name:         "busybox-regression",
			fixtureImage: "image-busybox",
			location:     "/bin/[",
			expected: []Classification{
				{
					Class: "busybox-binary",
					Metadata: map[string]string{
						"version": "1.35.0",
					},
				},
			},
			expectedErr: assert.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			c, err := NewClassificationCataloger(DefaultClassifiers)
			test.expectedErr(t, err)

			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			src, err := source.NewFromImage(img, "test-img")
			test.expectedErr(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			test.expectedErr(t, err)

			actualResults, err := c.Catalog(resolver)
			test.expectedErr(t, err)

			ok := false
			for actuaLoc, actualClassification := range actualResults {
				if actuaLoc.RealPath == test.location {
					ok = true
					assert.Equal(t, test.expected, actualClassification)
				}
			}

			if !ok {
				t.Fatalf("could not find test location=%q", test.location)
			}

		})
	}
}

func TestClassifierCataloger_DefaultClassifiers_NegativeCases(t *testing.T) {

	c, err := NewClassificationCataloger(DefaultClassifiers)
	assert.NoError(t, err)

	src, err := source.NewFromDirectory("test-fixtures/classifiers/negative")
	assert.NoError(t, err)

	resolver, err := src.FileResolver(source.SquashedScope)
	assert.NoError(t, err)

	actualResults, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(actualResults))

}
