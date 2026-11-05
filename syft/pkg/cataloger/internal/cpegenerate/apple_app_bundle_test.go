package cpegenerate

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func TestFromPackageAttributesAppleAppBundle(t *testing.T) {
	// The bundle identifiers, names, and versions below are the ones from
	// https://github.com/anchore/syft/issues/5429, where the NVD-matching vendor/product pairs
	// and match counts were verified against grype and the NVD dictionary.
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "google chrome: mapped bundle id yields the NVD vendor and product",
			p: pkg.Package{
				Name:    "Google Chrome",
				Version: "120.0.6099.109",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "com.google.Chrome",
					DisplayName:      "Google Chrome",
					ShortVersion:     "120.0.6099.109",
				},
			},
			expected: []string{
				"cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*",
			},
		},
		{
			name: "docker desktop: display-name CPE would match Docker Engine CVEs, mapped id does not",
			p: pkg.Package{
				Name:    "Docker",
				Version: "4.95.0",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "com.docker.docker",
					DisplayName:      "Docker",
					ShortVersion:     "4.95.0",
				},
			},
			expected: []string{
				"cpe:2.3:a:docker:desktop:4.95.0:*:*:*:*:*:*:*",
			},
		},
		{
			name: "zoom: trailing parenthesized build is kept out of the CPE version",
			p: pkg.Package{
				Name:    "zoom.us",
				Version: "7.2.2 (88465)",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "us.zoom.xos",
					DisplayName:      "zoom.us",
					ShortVersion:     "7.2.2 (88465)",
				},
			},
			expected: []string{
				"cpe:2.3:a:zoom:zoom:7.2.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "unmapped bundle id yields no CPE at all",
			p: pkg.Package{
				Name:    "Ghostty",
				Version: "1.3.1",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "com.mitchellh.ghostty",
					DisplayName:      "Ghostty",
					ShortVersion:     "1.3.1",
				},
			},
			expected: nil,
		},
		{
			name: "apple app bundle without metadata yields no CPE",
			p: pkg.Package{
				Name:    "Google Chrome",
				Version: "120.0.6099.109",
				Type:    pkg.AppleAppBundlePkg,
			},
			expected: nil,
		},
		{
			name: "apple app bundle without a bundle identifier yields no CPE",
			p: pkg.Package{
				Name:    "Slack",
				Version: "4.50.128",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					DisplayName:  "Slack",
					ShortVersion: "4.50.128",
				},
			},
			expected: nil,
		},
		{
			name: "version that is only a parenthesized build yields no CPE",
			p: pkg.Package{
				Name:    "zoom.us",
				Version: "(88465)",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "us.zoom.xos",
				},
			},
			expected: nil,
		},
		{
			name: "oversized version still bounded by the hostile-input guard",
			p: pkg.Package{
				Name:    "zoom.us",
				Version: "7.2.2 (88465" + string(make([]byte, 600)) + ")",
				Type:    pkg.AppleAppBundlePkg,
				Metadata: pkg.AppleAppBundleEntry{
					BundleIdentifier: "us.zoom.xos",
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := FromPackageAttributes(tt.p)

			var actualStrings []string
			for _, a := range actual {
				// the generated CPE carries the version from the mapping path, not from
				// a name-derived candidate: pin the source too
				assert.Equal(t, cpe.GeneratedSource, a.Source)
				actualStrings = append(actualStrings, a.Attributes.String())
			}
			sort.Strings(actualStrings)

			assert.Equal(t, tt.expected, actualStrings)
		})
	}
}
