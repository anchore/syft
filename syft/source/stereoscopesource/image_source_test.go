package stereoscopesource

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/internal/testutil"
	"github.com/anchore/syft/syft/source"
)

func Test_StereoscopeImage_Exclusions(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc       string
		input      string
		glob       string
		expected   int
		exclusions []string
	}{
		// NOTE: in the Dockerfile, /target is moved to /, which makes /really a top-level dir
		{
			input:      "image-simple",
			desc:       "a single path excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"/really/**"},
		},
		{
			input:      "image-simple",
			desc:       "a directly referenced directory is excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"/really"},
		},
		{
			input:      "image-simple",
			desc:       "a partial directory is not excluded",
			glob:       "**",
			expected:   3,
			exclusions: []string{"/reall"},
		},
		{
			input:      "image-simple",
			desc:       "exclude files deeper",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/nested/**"},
		},
		{
			input:      "image-simple",
			desc:       "files excluded with extension",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/*1.txt"},
		},
		{
			input:      "image-simple",
			desc:       "keep files with different extensions",
			glob:       "**",
			expected:   3,
			exclusions: []string{"**/target/**/*.jar"},
		},
		{
			input:      "image-simple",
			desc:       "file directly excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/somefile-1.txt"}, // file-1 renamed to somefile-1 in Dockerfile
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			imageName := strings.SplitN(imagetest.PrepareFixtureImage(t, "docker-archive", test.input), ":", 2)[1]

			img, err := stereoscope.GetImage(context.TODO(), imageName)
			require.NoError(t, err)
			require.NotNil(t, img)

			src := New(
				img,
				ImageConfig{
					Reference: imageName,
					Exclude: source.ExcludeConfig{
						Paths: test.exclusions,
					},
				},
			)

			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			contents, err := res.FilesByGlob(test.glob)
			require.NoError(t, err)

			assert.Len(t, contents, test.expected)
		})
	}
}

func Test_Describe(t *testing.T) {
	tests := []struct {
		name     string
		source   stereoscopeImageSource
		expected source.Description
	}{
		{
			name: "name from user input",
			source: stereoscopeImageSource{
				id: "some-id",
				metadata: source.ImageMetadata{
					UserInput: "user input",
				},
			},
			expected: source.Description{
				ID:   "some-id",
				Name: "user input",
			},
		},
	}

	for _, test := range tests {
		got := test.source.Describe()
		got.Metadata = nil // might want to test this, but do not to determine if the user input is userd
		require.Equal(t, test.expected, got)
	}
}
