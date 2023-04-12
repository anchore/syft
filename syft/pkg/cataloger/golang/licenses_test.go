package golang

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
)

func Test_LocalLicenseSearch(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "github.com/someorg/somename",
			version:  "v0.3.2",
			expected: "Apache-2.0",
		},
		{
			name:     "github.com/CapORG/CapProject",
			version:  "v4.111.5",
			expected: "MIT",
		},
	}

	wd, err := os.Getwd()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenses(GoCatalogerOpts{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            path.Join(wd, "test-fixtures", "licenses", "pkg", "mod"),
			})
			licenses, err := l.getLicenses(source.MockResolver{}, test.name, test.version)
			require.NoError(t, err)

			require.Len(t, licenses, 1)

			require.Equal(t, test.expected, licenses[0])
		})
	}
}

func Test_RemoteProxyLicenseSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := &bytes.Buffer{}
		uri := strings.TrimPrefix(strings.TrimSuffix(r.RequestURI, ".zip"), "/")

		parts := strings.Split(uri, "/@v/")
		modPath := parts[0]
		modVersion := parts[1]

		wd, err := os.Getwd()
		require.NoError(t, err)
		testDir := path.Join(wd, "test-fixtures", "licenses", "pkg", "mod", processCaps(modPath)+"@"+modVersion)

		archive := zip.NewWriter(buf)

		entries, err := os.ReadDir(testDir)
		require.NoError(t, err)
		for _, f := range entries {
			writer, err := archive.Create(f.Name())
			require.NoError(t, err)
			contents, err := os.ReadFile(path.Join(testDir, f.Name()))
			require.NoError(t, err)
			_, err = writer.Write(contents)
			require.NoError(t, err)
		}

		err = archive.Close()
		require.NoError(t, err)

		w.Header().Add("Content-Length", fmt.Sprintf("%d", buf.Len()))

		_, err = w.Write(buf.Bytes())
		require.NoError(t, err)
	}))
	defer server.Close()

	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "github.com/someorg/somename",
			version:  "v0.3.2",
			expected: "Apache-2.0",
		},
		{
			name:     "github.com/CapORG/CapProject",
			version:  "v4.111.5",
			expected: "MIT",
		},
	}

	modDir := path.Join(t.TempDir())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenses(GoCatalogerOpts{
				SearchRemoteLicenses: true,
				Proxy:                server.URL,
				LocalModCacheDir:     modDir,
			})

			licenses, err := l.getLicenses(source.MockResolver{}, test.name, test.version)
			require.NoError(t, err)

			require.Len(t, licenses, 1)

			require.Equal(t, test.expected, licenses[0])
		})
	}
}

func Test_processCaps(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "CycloneDX",
			expected: "!cyclone!d!x",
		},
		{
			name:     "Azure",
			expected: "!azure",
		},
		{
			name:     "xkcd",
			expected: "xkcd",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := processCaps(test.name)

			require.Equal(t, test.expected, got)
		})
	}
}

func Test_proxyForModulue(t *testing.T) {
	proxyString := "https://somewhere.org,direct"

	allProxies := []string{"https://somewhere.org", "direct"}
	directProxy := []string{"direct"}

	tests := []struct {
		module   string
		noProxy  string
		expected []string
	}{
		{
			module:   "github.com/anchore/syft",
			expected: allProxies,
		},
		{
			module:   "github.com/anchore/sbom-action",
			noProxy:  "*/anchore/*",
			expected: directProxy,
		},
		{
			module:   "github.com/anchore/sbom-action",
			noProxy:  "*/user/mod,*/anchore/sbom-action",
			expected: directProxy,
		},
	}

	for _, test := range tests {
		t.Run(test.module, func(t *testing.T) {
			got := remoteProxies(proxyString, test.noProxy, test.module)
			require.Equal(t, test.expected, got)
		})
	}
}
