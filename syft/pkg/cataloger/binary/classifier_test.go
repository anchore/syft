package binary

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_ClassifierCPEs(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		classifier binaryClassifier
		cpes       []string
	}{
		{
			name:    "no CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: binaryClassifier{
				Package:         "some-app",
				FileGlob:        ".*/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs:            []pkg.CPE{},
			},
			cpes: nil,
		},
		{
			name:    "one CPE",
			fixture: "test-fixtures/version.txt",
			classifier: binaryClassifier{
				Package:         "some-app",
				FileGlob:        ".*/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []pkg.CPE{
					pkg.MustCPE("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"),
				},
			},
			cpes: []string{
				"cpe:2.3:a:some:app:1.8:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "multiple CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: binaryClassifier{
				Package:         "some-app",
				FileGlob:        ".*/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []pkg.CPE{
					pkg.MustCPE("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"),
					pkg.MustCPE("cpe:2.3:a:some:apps:*:*:*:*:*:*:*:*"),
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
			resolver := source.NewMockResolverForPaths(test.fixture)
			locations, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)
			require.Len(t, locations, 1)
			location := locations[0]
			readCloser, err := resolver.FileContentsByLocation(location)
			require.NoError(t, err)
			pkgs, err := test.classifier.EvidenceMatcher(test.classifier, source.NewLocationReadCloser(location, readCloser))
			require.NoError(t, err)

			require.Len(t, pkgs, 1)

			p := pkgs[0]

			var cpes []string
			for _, c := range p.CPEs {
				cpes = append(cpes, pkg.CPEString(c))
			}
			require.Equal(t, test.cpes, cpes)
		})
	}
}
