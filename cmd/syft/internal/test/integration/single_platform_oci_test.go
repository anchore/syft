package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

// TestSinglePlatformOCIImage covers the single-image (non-index) OCI layouts, where syft used to report
// empty os/architecture metadata and silently accept any --platform. Both now come from the image config.
func TestSinglePlatformOCIImage(t *testing.T) {
	// a platform this fixture is never built for, so the mismatch is not host dependent
	unavailablePlatform, err := image.NewPlatform("linux/ppc64le")
	require.NoError(t, err)

	sources := map[string]image.Source{
		"oci-dir":     image.OciDirectorySource,
		"oci-archive": image.OciTarballSource,
	}

	for from, imageSource := range sources {
		t.Run(from, func(t *testing.T) {
			localPath := strings.TrimPrefix(imagetest.PrepareFixtureImage(t, imageSource, "image-distro-id"), string(imageSource)+":")

			t.Run("reports the platform from the image config", func(t *testing.T) {
				src, err := syft.GetSource(
					context.Background(),
					localPath,
					syft.DefaultGetSourceConfig().WithSources(from),
				)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, src.Close())
				})

				meta, ok := src.Describe().Metadata.(source.ImageMetadata)
				require.True(t, ok, "expected image metadata, got %T", src.Describe().Metadata)

				// the fixture is built for whatever the local docker daemon runs, so assert against the
				// config rather than a fixed platform
				assert.NotEmpty(t, meta.OS)
				assert.NotEmpty(t, meta.Architecture)
				assertConfigPlatform(t, meta.RawConfig, meta.OS, meta.Architecture)
			})

			t.Run("rejects a platform the image does not match", func(t *testing.T) {
				_, err := syft.GetSource(
					context.Background(),
					localPath,
					syft.DefaultGetSourceConfig().WithSources(from).WithPlatform(unavailablePlatform),
				)
				require.ErrorContains(t, err, "linux/ppc64le")
			})
		})
	}
}
