package stereoscopesource

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/artifact"
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

func Test_StereoscopeImageSource_ID(t *testing.T) {
	tests := []struct {
		name     string
		alias    source.Alias
		metadata source.ImageMetadata
		want     artifact.ID
	}{
		{
			name: "use raw manifest over chain ID or user input",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: func() artifact.ID {
				hasher := sha256.New()
				hasher.Write([]byte("raw-manifest"))
				return artifact.ID(fmt.Sprintf("%x", hasher.Sum(nil)))
			}(),
		},
		{
			name: "use chain ID over user input",
			metadata: source.ImageMetadata{
				//UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
			},
			want: func() artifact.ID {
				metadata := []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				}
				return artifact.ID(strings.TrimPrefix(calculateChainID(metadata), "sha256:"))
			}(),
		},
		{
			name: "use user input last",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: func() artifact.ID {
				hasher := sha256.New()
				hasher.Write([]byte("user-input"))
				return artifact.ID(fmt.Sprintf("%x", hasher.Sum(nil)))
			}(),
		},
		{
			name: "without alias (first)",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: "85298926ecd92ed57688f13039017160cd728f04dd0d2d10a10629007106f107",
		},
		{
			name: "always consider alias (first)",
			alias: source.Alias{
				Name:    "alias",
				Version: "version",
			},
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: "a8717e42449960c1dd4963f2f22bd69c7c105e7e82445be0a65aa1825d62ff0d",
		},
		{
			name: "without alias (last)",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: "ab0dff627d80b9753193d7280bec8f45e8ec6b4cb0912c6fffcf7cd782d9739e",
		},
		{
			name: "always consider alias (last)",
			alias: source.Alias{
				Name:    "alias",
				Version: "version",
			},
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: "fe86c0eecd5654d3c0c0b2176aa394aef6440347c241aa8d9b628dfdde4287cf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deriveIDFromStereoscopeImage(tt.alias, tt.metadata))
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
