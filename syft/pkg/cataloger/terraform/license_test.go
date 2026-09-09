package terraform

import (
	"archive/zip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestFindLocalLicenses(t *testing.T) {
	ctx := pkgtest.Context(t)
	resolver := fileresolver.NewFromUnindexedDirectory(filepath.Join("testdata", "with-licenses"))
	lr := newTerraformLicenseResolver(DefaultCatalogerConfig())

	t.Run("license exists", func(t *testing.T) {
		found := lr.findLocalLicenses(ctx, resolver, "", "registry.terraform.io/hashicorp/aws", "5.72.1")
		require.Len(t, found, 1)
		assert.Equal(t, "MIT", found[0].SPDXExpression)
	})

	t.Run("no license", func(t *testing.T) {
		found := lr.findLocalLicenses(ctx, resolver, "", "registry.terraform.io/hashicorp/google", "6.8.0")
		assert.Empty(t, found)
	})
}

func TestParseProviderURL(t *testing.T) {
	tests := []struct {
		input     string
		namespace string
		provider  string
		wantErr   bool
	}{
		{
			input:     "registry.terraform.io/hashicorp/aws",
			namespace: "hashicorp",
			provider:  "aws",
		},
		{
			input:     "registry.terraform.io/hashicorp/google",
			namespace: "hashicorp",
			provider:  "google",
		},
		{
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ns, prov, err := parseProviderURL(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.namespace, ns)
			assert.Equal(t, tt.provider, prov)
		})
	}
}

func TestFindRemoteLicenses(t *testing.T) {
	zipData := createTestProviderZip(t)

	downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer downloadServer.Close()

	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"download_url": "%s/terraform-provider-test.zip"}`, downloadServer.URL)
	}))
	defer registryServer.Close()

	cfg := CatalogerConfig{
		SearchRemoteLicenses: true,
		RegistryBaseURL:      registryServer.URL,
	}
	lr := newTerraformLicenseResolver(cfg)
	ctx := pkgtest.Context(t)

	licenses, err := lr.findRemoteLicenses(ctx, "registry.terraform.io/hashicorp/aws", "5.72.1")
	require.NoError(t, err)
	require.Len(t, licenses, 1)
	assert.Equal(t, "MIT", licenses[0].SPDXExpression)
	assert.Empty(t, licenses[0].Locations.ToSlice())
}

func createTestProviderZip(t *testing.T) []byte {
	t.Helper()

	licenseContent, err := os.ReadFile(filepath.Join("testdata", "with-licenses", ".terraform", "providers",
		"registry.terraform.io", "hashicorp", "aws", "5.72.1", "linux_amd64", "LICENSE.txt"))
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(tmpFile)
	require.NoError(t, err)

	w := zip.NewWriter(f)
	entry, err := w.Create("LICENSE.txt")
	require.NoError(t, err)
	_, err = entry.Write(licenseContent)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	return data
}
