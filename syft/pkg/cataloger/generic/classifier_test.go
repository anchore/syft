package generic

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
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
				Package: "some-app",
				FilepathPatterns: []*regexp.Regexp{
					regexp.MustCompile(".*/version.txt"),
				},
				EvidencePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?m)my-verison:(?P<version>[0-9.]+)`),
				},
				CPEs: []pkg.CPE{},
			},
			cpes: nil,
		},
		{
			name:    "one CPE",
			fixture: "test-fixtures/version.txt",
			classifier: Classifier{
				Package: "some-app",
				FilepathPatterns: []*regexp.Regexp{
					regexp.MustCompile(".*/version.txt"),
				},
				EvidencePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?m)my-verison:(?P<version>[0-9.]+)`),
				},
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
			classifier: Classifier{
				Package: "some-app",
				FilepathPatterns: []*regexp.Regexp{
					regexp.MustCompile(".*/version.txt"),
				},
				EvidencePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?m)my-verison:(?P<version>[0-9.]+)`),
				},
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
			p, _, err := test.classifier.Examine(source.NewLocationReadCloser(location, readCloser))
			require.NoError(t, err)

			var cpes []string
			for _, c := range p.CPEs {
				cpes = append(cpes, pkg.CPEString(c))
			}
			require.Equal(t, test.cpes, cpes)
		})
	}
}
func TestFilepathMatches(t *testing.T) {
	tests := []struct {
		name                string
		location            source.Location
		patterns            []string
		expectedMatches     bool
		expectedNamedGroups map[string]string
	}{
		{
			name: "simple-filename-match",
			location: source.Location{
				Coordinates: source.Coordinates{
					RealPath: "python2.7",
				},
			},
			patterns: []string{
				`python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: true,
		},
		{
			name: "filepath-match",
			location: source.Location{
				Coordinates: source.Coordinates{
					RealPath: "/usr/bin/python2.7",
				},
			},
			patterns: []string{
				`python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: true,
		},
		{
			name: "virtual-filepath-match",
			location: source.Location{
				VirtualPath: "/usr/bin/python2.7",
			},
			patterns: []string{
				`python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: true,
		},
		{
			name: "full-filepath-match",
			location: source.Location{
				VirtualPath: "/usr/bin/python2.7",
			},
			patterns: []string{
				`.*/bin/python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: true,
		},
		{
			name: "anchored-filename-match-FAILS",
			location: source.Location{
				Coordinates: source.Coordinates{
					RealPath: "/usr/bin/python2.7",
				},
			},
			patterns: []string{
				`^python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: false,
		},
		{
			name:     "empty-filename-match-FAILS",
			location: source.Location{},
			patterns: []string{
				`^python([0-9]+\.[0-9]+)$`,
			},
			expectedMatches: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var patterns []*regexp.Regexp
			for _, p := range test.patterns {
				patterns = append(patterns, regexp.MustCompile(p))
			}
			actualMatches, actualNamedGroups := FilepathMatches(patterns, test.location)
			assert.Equal(t, test.expectedMatches, actualMatches)
			assert.Equal(t, test.expectedNamedGroups, actualNamedGroups)
		})
	}
}
