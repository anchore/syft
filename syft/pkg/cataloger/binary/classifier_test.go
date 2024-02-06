package binary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

func Test_ClassifierCPEs(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		classifier Classifier
		cpes       []string
	}{
		{
			name:    "no CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: Classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: FileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs:            []cpe.CPE{},
			},
			cpes: nil,
		},
		{
			name:    "one Attributes",
			fixture: "test-fixtures/version.txt",
			classifier: Classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: FileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				},
			},
			cpes: []string{
				"cpe:2.3:a:some:app:1.8:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "multiple CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: Classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: FileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
					cpe.Must("cpe:2.3:a:some:apps:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				},
			},
			cpes: []string{
				"cpe:2.3:a:some:app:1.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:some:apps:1.8:*:*:*:*:*:*:*",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := file.NewMockResolverForPaths(test.fixture)
			ls, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)
			require.Len(t, ls, 1)

			pkgs, err := test.classifier.EvidenceMatcher(resolver, test.classifier, ls[0])
			require.NoError(t, err)

			require.Len(t, pkgs, 1)

			p := pkgs[0]

			var cpes []string
			for _, c := range p.CPEs {
				cpes = append(cpes, c.Attributes.String())
			}
			require.Equal(t, test.cpes, cpes)
		})
	}
}

func TestClassifier_MarshalJSON(t *testing.T) {

	tests := []struct {
		name       string
		classifier Classifier
		want       string
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name: "go case",
			classifier: Classifier{
				Class:           "class",
				FileGlob:        "glob",
				EvidenceMatcher: FileContentsVersionMatcher(".thing"),
				Package:         "pkg",
				PURL: packageurl.PackageURL{
					Type:       "type",
					Namespace:  "namespace",
					Name:       "name",
					Version:    "version",
					Qualifiers: nil,
					Subpath:    "subpath",
				},
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*", cpe.GeneratedSource)},
			},
			want: `{"class":"class","fileGlob":"glob","package":"pkg","purl":"pkg:type/namespace/name@version#subpath","cpes":["cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			cfg := tt.classifier
			got, err := cfg.MarshalJSON()
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}
