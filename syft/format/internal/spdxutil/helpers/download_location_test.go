package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_DownloadLocation(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: NOASSERTION,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "",
				},
			},
			expected: NONE,
		},
		{
			name: "from npm package-lock should include resolved",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockEntry{
					Resolved: "http://package-lock.test",
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "from npm package-lock empty should be NONE",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockEntry{
					Resolved: "",
				},
			},
			expected: NONE,
		},
		{
			name: "from php installed.json",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "http://package-lock.test",
					},
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "",
					},
				},
			},
			expected: "NONE",
		},
		{
			name: "from php composer.lock",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "http://package-lock.test",
					},
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "",
					},
				},
			},
			expected: "NONE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, DownloadLocation(test.input))
		})
	}
}
