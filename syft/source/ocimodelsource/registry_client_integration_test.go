package ocimodelsource

import (
	"context"
	"io"
	stdlog "log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

// TestFetchAndStore_safetensors_inMemoryRegistry drives the full OCI fetch +
// on-disk staging pipeline against a real (but in-process) registry, so nothing
// touches the network. It pushes a synthetic Docker AI safetensors artifact —
// config blob + one safetensors weight layer + a model.file companion + a
// license layer — then asserts that fetchModelArtifact classifies the layers and
// that fetchAndStoreModelHeaders stages every blob under the correct media type
// with its bytes intact. This is the seam the mock-resolver merge tests assume is
// correct; the staged content here is deliberately format-agnostic (header
// parsing is covered in the ai package).
func TestFetchAndStore_safetensors_inMemoryRegistry(t *testing.T) {
	ctx := context.Background()

	configMediaType := modelConfigMediaTypePrefix + "v0.2+json"
	weightHeader := []byte("safetensors-header-bytes")
	modelFile := []byte(`{"architectures":["LlamaForCausalLM"],"_name_or_path":"org/model"}`)
	license := []byte("MIT license text")

	img := mutate.ConfigMediaType(empty.Image, types.MediaType(configMediaType))
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img, err := mutate.Append(img,
		layer(weightHeader, safetensorsLayerMediaType),
		layer(modelFile, modelFileMediaType),
		layer(license, licenseMediaType),
	)
	require.NoError(t, err)

	// in-memory registry; localhost so go-containerregistry selects the http scheme
	server := httptest.NewServer(registry.New(registry.Logger(stdlog.New(io.Discard, "", 0))))
	defer server.Close()
	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	refStr := "localhost:" + u.Port() + "/testmodel:latest"

	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, remote.WithContext(ctx)))

	client := newRegistryClient(&image.RegistryOptions{InsecureUseHTTP: true})

	art, err := client.fetchModelArtifact(ctx, refStr)
	require.NoError(t, err)
	assert.Equal(t, modelFormatSafeTensors, art.Format)
	assert.Len(t, art.SafeTensorsLayers, 1)
	assert.Len(t, art.CompanionLayers, 2) // model.file + license
	assert.Empty(t, art.GGUFLayers)
	assert.NotEmpty(t, art.RawConfig)
	assert.NotEmpty(t, art.ManifestDigest)

	tempDir, resolver, err := fetchAndStoreModelHeaders(ctx, client, art)
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	assert.Equal(t, refStr, resolver.ImageReference())

	// every blob is staged under its own media type with bytes intact — this
	// exercises fetchBlobRange's short-read (ErrUnexpectedEOF) branch, since each
	// blob is far smaller than the fetch cap, plus all four staging helpers.
	assertServesBytes(t, resolver, safetensorsLayerMediaType, weightHeader)
	assertServesBytes(t, resolver, modelFileMediaType, modelFile)
	assertServesBytes(t, resolver, licenseMediaType, license)

	cfgLocs, err := resolver.FilesByMediaType(configMediaType)
	require.NoError(t, err)
	require.Len(t, cfgLocs, 1)
}

func layer(content []byte, mediaType string) mutate.Addendum {
	return mutate.Addendum{
		Layer:     static.NewLayer(content, types.MediaType(mediaType)),
		MediaType: types.MediaType(mediaType),
	}
}

func assertServesBytes(t *testing.T, resolver *fileresolver.ContainerImageModel, mediaType string, want []byte) {
	t.Helper()
	locs, err := resolver.FilesByMediaType(mediaType)
	require.NoError(t, err)
	require.Len(t, locs, 1)

	rc, err := resolver.FileContentsByLocation(locs[0])
	require.NoError(t, err)
	defer rc.Close()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
