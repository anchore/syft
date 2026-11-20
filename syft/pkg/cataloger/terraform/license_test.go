package terraform

import (
	"archive/zip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		host      string
		namespace string
		provider  string
		wantErr   bool
	}{
		{
			input:     "registry.terraform.io/hashicorp/aws",
			host:      "registry.terraform.io",
			namespace: "hashicorp",
			provider:  "aws",
		},
		{
			input:     "registry.opentofu.org/hashicorp/google",
			host:      "registry.opentofu.org",
			namespace: "hashicorp",
			provider:  "google",
		},
		{
			input:     "Registry.Terraform.IO/hashicorp/aws",
			host:      "registry.terraform.io",
			namespace: "hashicorp",
			provider:  "aws",
		},
		{
			input:   "invalid",
			wantErr: true,
		},
		{
			input:   "registry.terraform.io/hashicorp/aws/extra",
			wantErr: true,
		},
		{
			input:   "registry.terraform.io//aws",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, ns, prov, err := parseProviderURL(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.host, host)
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
		assert.Equal(t, "/v1/providers/hashicorp/aws/5.72.1/download/linux/amd64", r.URL.Path)
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
	assert.Equal(t, []string{downloadServer.URL + "/terraform-provider-test.zip#LICENSE.txt"}, licenses[0].URLs)
	assert.Empty(t, licenses[0].Locations.ToSlice())
}

func TestFindRemoteLicenses_ServiceDiscovery(t *testing.T) {
	zipData := createTestProviderZip(t)

	var configuredRegistryHit bool
	configuredRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		configuredRegistryHit = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer configuredRegistry.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"providers.v1": "/api/providers/"}`)
	})
	mux.HandleFunc("/api/providers/opentofu/random/3.6.0/download/linux/amd64", func(w http.ResponseWriter, _ *http.Request) {
		// a relative download URL should be resolved against the registry endpoint
		fmt.Fprint(w, `{"download_url": "/archives/random.zip"}`)
	})
	mux.HandleFunc("/archives/random.zip", func(w http.ResponseWriter, _ *http.Request) {
		w.Write(zipData)
	})
	otherRegistry := httptest.NewTLSServer(mux)
	defer otherRegistry.Close()

	lr := newTerraformLicenseResolver(CatalogerConfig{
		SearchRemoteLicenses: true,
		RegistryBaseURL:      configuredRegistry.URL,
	})
	lr.client = otherRegistry.Client()

	host := strings.TrimPrefix(otherRegistry.URL, "https://")
	licenses, err := lr.findRemoteLicenses(pkgtest.Context(t), host+"/opentofu/random", "3.6.0")
	require.NoError(t, err)
	require.Len(t, licenses, 1)
	assert.Equal(t, "MIT", licenses[0].SPDXExpression)
	assert.Equal(t, []string{otherRegistry.URL + "/archives/random.zip#LICENSE.txt"}, licenses[0].URLs)
	assert.False(t, configuredRegistryHit, "providers from other registries must not be looked up in the configured registry")
}

func TestFindRemoteLicenses_Errors(t *testing.T) {
	tests := []struct {
		name     string
		registry http.HandlerFunc
		download http.HandlerFunc
		wantErr  string
	}{
		{
			name: "registry returns non-200",
			registry: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: "status 404",
		},
		{
			name: "registry returns empty download URL",
			registry: func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, `{"download_url": ""}`)
			},
			wantErr: "empty download URL",
		},
		{
			name: "registry returns invalid JSON",
			registry: func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, `not json`)
			},
			wantErr: "unable to decode",
		},
		{
			name: "download returns non-200",
			download: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			wantErr: "status 403",
		},
		{
			name: "download is not a zip",
			download: func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, "definitely not a zip archive")
			},
			wantErr: "unable to read provider zip",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			download := tt.download
			if download == nil {
				zipData := createTestProviderZip(t)
				download = func(w http.ResponseWriter, _ *http.Request) { w.Write(zipData) }
			}
			downloadServer := httptest.NewServer(download)
			defer downloadServer.Close()

			registry := tt.registry
			if registry == nil {
				registry = func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprintf(w, `{"download_url": "%s/provider.zip"}`, downloadServer.URL)
				}
			}
			registryServer := httptest.NewServer(registry)
			defer registryServer.Close()

			lr := newTerraformLicenseResolver(CatalogerConfig{
				SearchRemoteLicenses: true,
				RegistryBaseURL:      registryServer.URL,
			})

			// use a distinct version per case so results are never shared through the license cache
			licenses, err := lr.findRemoteLicenses(pkgtest.Context(t), "registry.terraform.io/hashicorp/aws", fmt.Sprintf("0.0.%d", i))
			require.ErrorContains(t, err, tt.wantErr)
			assert.Empty(t, licenses)
		})
	}
}

func TestGetLicenses(t *testing.T) {
	zipData := createTestProviderZip(t)
	resolver := fileresolver.NewFromUnindexedDirectory(filepath.Join("testdata", "with-licenses"))

	var registryHits int
	newRegistry := func(t *testing.T) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/provider.zip", func(w http.ResponseWriter, _ *http.Request) {
			w.Write(zipData)
		})
		mux.HandleFunc("/v1/providers/", func(w http.ResponseWriter, r *http.Request) {
			registryHits++
			fmt.Fprint(w, `{"download_url": "/provider.zip"}`)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		return srv
	}

	tests := []struct {
		name         string
		remote       bool
		provider     string
		version      string
		wantLicense  bool
		wantLocation bool
		wantHits     int
	}{
		{
			name:         "local cache wins without touching the network",
			remote:       true,
			provider:     "registry.terraform.io/hashicorp/aws",
			version:      "5.72.1",
			wantLicense:  true,
			wantLocation: true,
			wantHits:     0,
		},
		{
			name:     "remote disabled does not touch the network",
			remote:   false,
			provider: "registry.terraform.io/hashicorp/google",
			version:  "6.8.0",
			wantHits: 0,
		},
		{
			name:        "remote used when local cache is missing",
			remote:      true,
			provider:    "registry.terraform.io/hashicorp/google",
			version:     "6.8.0",
			wantLicense: true,
			wantHits:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registryHits = 0
			srv := newRegistry(t)
			lr := newTerraformLicenseResolver(CatalogerConfig{
				SearchRemoteLicenses: tt.remote,
				RegistryBaseURL:      srv.URL,
			})

			got := lr.getLicenses(pkgtest.Context(t), resolver, "", tt.provider, tt.version).ToSlice()
			assert.Equal(t, tt.wantHits, registryHits)
			if !tt.wantLicense {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			assert.Equal(t, "MIT", got[0].SPDXExpression)
			assert.Equal(t, tt.wantLocation, !got[0].Locations.Empty())
		})
	}
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
