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

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func Test_LocalLicenseSearch(t *testing.T) {
	loc1 := file.NewLocation("github.com/someorg/somename@v0.3.2/LICENSE")
	loc2 := file.NewLocation("github.com/!cap!o!r!g/!cap!project@v4.111.5/LICENSE.txt")

	tests := []struct {
		name     string
		version  string
		expected pkg.License
	}{
		{
			name:    "github.com/someorg/somename",
			version: "v0.3.2",
			expected: pkg.License{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				Locations:      file.NewLocationSet(loc1),
				URLs:           internal.NewStringSet(),
			},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			expected: pkg.License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				Locations:      file.NewLocationSet(loc2),
				URLs:           internal.NewStringSet(),
			},
		},
	}

	wd, err := os.Getwd()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenses(
				GoCatalogerOpts{
					searchLocalModCacheLicenses: true,
					localModCacheDir:            path.Join(wd, "test-fixtures", "licenses", "pkg", "mod"),
				},
			)
			licenses, err := l.getLicenses(fileresolver.Empty{}, test.name, test.version)
			require.NoError(t, err)

			require.Len(t, licenses, 1)

			require.Equal(t, test.expected, licenses[0])
		})
	}
}

func Test_RemoteProxyLicenseSearch(t *testing.T) {
	loc1 := file.NewLocation("github.com/someorg/somename@v0.3.2/LICENSE")
	loc2 := file.NewLocation("github.com/!cap!o!r!g/!cap!project@v4.111.5/LICENSE.txt")

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
			// the zip files downloaded contain a path to the repo that somewhat matches where it ends up on disk,
			// so prefix entries with something similar
			writer, err := archive.Create(path.Join("github.com/something/some@version", f.Name()))
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
		expected pkg.License
	}{
		{
			name:    "github.com/someorg/somename",
			version: "v0.3.2",
			expected: pkg.License{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				Locations:      file.NewLocationSet(loc1),
				URLs:           internal.NewStringSet(),
			},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			expected: pkg.License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				Locations:      file.NewLocationSet(loc2),
				URLs:           internal.NewStringSet(),
			},
		},
	}

	modDir := path.Join(t.TempDir())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenses(GoCatalogerOpts{
				searchRemoteLicenses: true,
				proxies:              []string{server.URL},
				localModCacheDir:     modDir,
			})

			licenses, err := l.getLicenses(fileresolver.Empty{}, test.name, test.version)
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

func Test_remotesForModule(t *testing.T) {
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
			got := remotesForModule(allProxies, strings.Split(test.noProxy, ","), test.module)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_findVersionPath(t *testing.T) {
	f := os.DirFS("test-fixtures/zip-fs")
	vp := findVersionPath(f, ".")
	require.Equal(t, "github.com/someorg/somepkg@version", vp)
}
