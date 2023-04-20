package binary

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

func Test_ClassifierCPEs(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		classifier classifier
		cpes       []string
	}{
		{
			name:    "no CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs:            []cpe.CPE{},
			},
			cpes: nil,
		},
		{
			name:    "one CPE",
			fixture: "test-fixtures/version.txt",
			classifier: classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"),
				},
			},
			cpes: []string{
				"cpe:2.3:a:some:app:1.8:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "multiple CPEs",
			fixture: "test-fixtures/version.txt",
			classifier: classifier{
				Package:         "some-app",
				FileGlob:        "**/version.txt",
				EvidenceMatcher: fileContentsVersionMatcher(`(?m)my-verison:(?P<version>[0-9.]+)`),
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"),
					cpe.Must("cpe:2.3:a:some:apps:*:*:*:*:*:*:*:*"),
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
				cpes = append(cpes, cpe.String(c))
			}
			require.Equal(t, test.cpes, cpes)
		})
	}
}
