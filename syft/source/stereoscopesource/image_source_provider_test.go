package stereoscopesource

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/source"
)

func Test_stereoscopeImageSourceProvider_layerSquashes(t *testing.T) {
	img, err := random.Image(1024, 3)
	require.NoError(t, err)
	tag, err := name.NewTag("localhost/layer-squashes:latest")
	require.NoError(t, err)
	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.WriteToFile(archive, tag, img))

	provide := func(t *testing.T, ctx context.Context) *stereoscopeImageSource {
		providers := Providers(ProviderConfig{
			StereoscopeImageProviderConfig: stereoscope.ImageProviderConfig{UserInput: archive},
		})
		for _, p := range providers {
			if p.Value.Name() != image.DockerTarballSource {
				continue
			}
			src, err := p.Value.Provide(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, src.Close()) })
			return src.(*stereoscopeImageSource)
		}
		t.Fatalf("no %s provider", image.DockerTarballSource)
		return nil
	}

	lazy := provide(t, context.Background())
	eager := provide(t, internal.WithEagerLayerSquashes(context.Background()))

	// lower layers are built on first use unless eager was asked for, the top is the image squash either way
	require.Len(t, lazy.image.Layers, 3)
	for idx := range lazy.image.Layers {
		_, isTree := lazy.image.Layers[idx].SquashedTree.(*filetree.FileTree)
		assert.Equalf(t, idx == 2, isTree, "lazy layer %d", idx)
		assert.IsTypef(t, &filetree.FileTree{}, eager.image.Layers[idx].SquashedTree, "eager layer %d", idx)
	}

	// every scope sees the same files either way
	for _, scope := range []source.Scope{source.SquashedScope, source.AllLayersScope, source.DeepSquashedScope} {
		t.Run(string(scope), func(t *testing.T) {
			files := func(src *stereoscopeImageSource) []string {
				res, err := src.FileResolver(scope)
				require.NoError(t, err)
				locs, err := res.FilesByGlob("**/*")
				require.NoError(t, err)
				var out []string
				for _, l := range locs {
					out = append(out, l.RealPath+"@"+l.FileSystemID)
				}
				return out
			}
			want := files(eager)
			require.NotEmpty(t, want)
			assert.ElementsMatch(t, want, files(lazy))
		})
	}
}
