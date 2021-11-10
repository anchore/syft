package file

import (
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

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
			actualMatches, actualNamedGroups := filepathMatches(patterns, test.location)
			assert.Equal(t, test.expectedMatches, actualMatches)
			assert.Equal(t, test.expectedNamedGroups, actualNamedGroups)
		})
	}
}
