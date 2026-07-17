package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

// TestMultiPlatformOCIImageSelection verifies that syft can load a single platform out of a
// multi-platform OCI image on disk (both --from oci-dir and --from oci-archive) by selecting the
// image that matches the requested platform.
func TestMultiPlatformOCIImageSelection(t *testing.T) {
	remoteImage := "quay.io/skopeo/stable:v1.20.0-immutable"

	// Per-platform image config digests within the multi-platform index, obtained from the OCI layout
	// (see anchore/stereoscope integration tests: TestPlatformSelectionWithOciLocalSources).
	expectedDigest := map[string]string{
		"arm64":   "sha256:59de7b16fa64a0a21873c02622c45259e89dbbe29e33afd77821f6106d537c95",
		"s390x":   "sha256:121427690da1f522eb73d58432b070a96c1b6be6b2aa0603dc76f029febdf2b1",
		"amd64":   "sha256:a8951deb17b620ff20ca25c0bfa82eca93560711def5bf096ee1e38a11742658",
		"ppc64le": "sha256:642fb8a0ef786227bb12ad0da6326b97809c162b86329f5e39ad990672cee5da",
	}

	// syft --from source tag -> stereoscope OCI source used to prepare the local fixture
	sources := map[string]image.Source{
		"oci-dir":     image.OciDirectorySource,
		"oci-archive": image.OciTarballSource,
	}

	for from, imageSource := range sources {
		t.Run(from, func(t *testing.T) {
			localPath := imagetest.PrepareMultiplatformFixtureImage(t, imageSource, remoteImage)
			for _, arch := range []string{"amd64", "arm64", "s390x", "ppc64le"} {
				t.Run(fmt.Sprintf("linux/%s", arch), func(t *testing.T) {
					platform, err := image.NewPlatform("linux/" + arch)
					require.NoError(t, err)

					src, err := syft.GetSource(
						context.Background(),
						localPath,
						syft.DefaultGetSourceConfig().WithSources(from).WithPlatform(platform),
					)
					require.NoError(t, err)
					t.Cleanup(func() {
						require.NoError(t, src.Close())
					})

					meta, ok := src.Describe().Metadata.(source.ImageMetadata)
					require.True(t, ok, "expected image metadata, got %T", src.Describe().Metadata)

					// The raw config of the selected image must match the requested platform...
					assertConfigPlatform(t, meta.RawConfig, "linux", arch)
					// ...and it must be the exact per-platform image from the multi-platform index.
					assert.Equal(t, expectedDigest[arch], meta.ID)
				})
			}
		})
	}
}

// TestMultiPlatformOCIImageSelection_UnavailablePlatform verifies that requesting a platform not present
// in the multi-platform OCI image results in an error rather than silently selecting the wrong image.
func TestMultiPlatformOCIImageSelection_UnavailablePlatform(t *testing.T) {
	remoteImage := "quay.io/skopeo/stable:v1.20.0-immutable"

	// windows/amd64 is not present in this linux-only multi-platform image
	platform, err := image.NewPlatform("windows/amd64")
	require.NoError(t, err)

	sources := map[string]image.Source{
		"oci-dir":     image.OciDirectorySource,
		"oci-archive": image.OciTarballSource,
	}

	for from, imageSource := range sources {
		t.Run(from, func(t *testing.T) {
			localPath := imagetest.PrepareMultiplatformFixtureImage(t, imageSource, remoteImage)

			_, err := syft.GetSource(
				context.Background(),
				localPath,
				syft.DefaultGetSourceConfig().WithSources(from).WithPlatform(platform),
			)
			require.ErrorContains(t, err, "windows/amd64")
		})
	}
}

// TestMultiPlatformOCIImageSelection_DefaultPlatform verifies that not specifying a platform results
// in the current platform being selected.
func TestMultiPlatformOCIImageSelection_DefaultPlatform(t *testing.T) {
	remoteImage := "quay.io/skopeo/stable:v1.20.0-immutable"

	sources := map[string]image.Source{
		"oci-dir":     image.OciDirectorySource,
		"oci-archive": image.OciTarballSource,
	}

	for from, imageSource := range sources {
		t.Run(from, func(t *testing.T) {
			localPath := imagetest.PrepareMultiplatformFixtureImage(t, imageSource, remoteImage)

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

			// The raw config of the selected image must match the current platform
			assertConfigPlatform(t, meta.RawConfig, "linux", runtime.GOARCH)
		})
	}
}

// assertConfigPlatform asserts the os/architecture recorded in a raw OCI image config document.
func assertConfigPlatform(t *testing.T, rawConfig []byte, os, architecture string) {
	t.Helper()
	require.NotEmpty(t, rawConfig)

	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	require.NoError(t, json.Unmarshal(rawConfig, &cfg))

	assert.Equal(t, os, cfg.OS)
	assert.Equal(t, architecture, cfg.Architecture)
}
