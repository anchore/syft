package stereoscopesource

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

func Test_stereoscopeImageSourceProvider_imageSquashOnly(t *testing.T) {
	img, err := random.Image(1024, 3)
	require.NoError(t, err)
	tag, err := name.NewTag("localhost/squash-only:latest")
	require.NoError(t, err)
	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.WriteToFile(archive, tag, img))

	provide := func(t *testing.T, squashOnly bool) source.Source {
		providers := Providers(ProviderConfig{
			StereoscopeImageProviderConfig: stereoscope.ImageProviderConfig{UserInput: archive},
			ImageSquashOnly:                squashOnly,
		})
		for _, p := range providers {
			if p.Value.Name() != image.DockerTarballSource {
				continue
			}
			src, err := p.Value.Provide(context.Background())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, src.Close()) })
			return src
		}
		t.Fatalf("no %s provider", image.DockerTarballSource)
		return nil
	}

	tests := []struct {
		name       string
		squashOnly bool
		scope      source.Scope
		wantErr    require.ErrorAssertionFunc
	}{
		{name: "full read, squashed", scope: source.SquashedScope, wantErr: require.NoError},
		{name: "full read, all layers", scope: source.AllLayersScope, wantErr: require.NoError},
		{name: "full read, deep squashed", scope: source.DeepSquashedScope, wantErr: require.NoError},
		{name: "squash only, squashed", squashOnly: true, scope: source.SquashedScope, wantErr: require.NoError},
		// the per-layer resolvers would dereference the dropped layer squashes, so refuse up front
		{name: "squash only, all layers", squashOnly: true, scope: source.AllLayersScope, wantErr: require.Error},
		{name: "squash only, deep squashed", squashOnly: true, scope: source.DeepSquashedScope, wantErr: require.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provide(t, tt.squashOnly).FileResolver(tt.scope)
			tt.wantErr(t, err)
		})
	}
}
