package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeExternalReferences(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected *[]cyclonedx.ExternalReference
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with valid URL",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with invalid URL but valid Homepage",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL:      "b-place",
					Homepage: "http://b-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://b-place.gov", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from cargo lock",
			input: pkg.Package{
				Name:     "ansi_term",
				Version:  "0.12.1",
				Language: pkg.Rust,
				Type:     pkg.RustPkg,
				Licenses: pkg.NewLicenseSet(),
				Metadata: pkg.RustCargoLockEntry{
					Name:     "ansi_term",
					Version:  "0.12.1",
					Source:   "registry+https://github.com/rust-lang/crates.io-index",
					Checksum: "d52a9bb7ec0cf484c551830a7ce27bd20d67eac647e1befb56b0be4ee39a55d2",
					Dependencies: []string{
						"winapi",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "registry+https://github.com/rust-lang/crates.io-index", Type: cyclonedx.ERTypeDistribution},
			},
		},
		{
			name: "from npm with homepage",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL:      "http://a-place.gov",
					Homepage: "http://homepage",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeDistribution},
				{URL: "http://homepage", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.RubyGemspec{
					Homepage: "http://a-place.gov",
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeWebsite},
			},
		},
		{
			name: "from python direct url",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
						URL: "http://a-place.gov",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeVCS},
			},
		},
		{
			name: "from python direct url with commit",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
						URL:      "http://a-place.gov",
						CommitID: "test",
					},
				},
			},
			expected: &[]cyclonedx.ExternalReference{
				{URL: "http://a-place.gov", Type: cyclonedx.ERTypeVCS, Comment: "commit: test"},
			},
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "",
				},
			},
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeExternalReferences(test.input))
		})
	}
}

func Test_encodeSourcePackage(t *testing.T) {
	rpm_epoch := 32
	tests := []struct {
		name     string
		input    pkg.Package
		expected *cyclonedx.ExternalReference
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Name:    "libc-utils",
				Version: "0.7.2-r3",
				Type:    pkg.ApkPkg,
				PURL:    "pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64&distro=alpine-3.16.3&upstream=libc-dev",
				Metadata: pkg.ApkDBEntry{
					Package:       "libc-utils",
					OriginPackage: "libc-dev",
					Version:       "0.7.2-r3",
					Architecture:  "x86_64",
				},
			},
			expected: &cyclonedx.ExternalReference{
				Type: cyclonedx.ERTypeSourceDistribution, URL: "pkg:apk/alpine/libc-dev@0.7.2-r3&arch=source&distro=alpine-3.16.3",
			},
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				Name:    "libpam-runtime",
				Version: "1.5.2-6+deb12u1",
				Type:    pkg.DebPkg,
				PURL:    "pkg:deb/debian/libpam-runtime@1.5.2-6%2Bdeb12u1?arch=all&distro=debian-12&upstream=pam",
				Metadata: pkg.DpkgDBEntry{
					Package:      "libpam-runtime",
					Version:      "1.5.2-6+deb12u1",
					Source:       "pam",
					Architecture: "all",
				},
			},
			expected: &cyclonedx.ExternalReference{
				Type: cyclonedx.ERTypeSourceDistribution, URL: "pkg:deb/debian/pam@1.5.2-6%2Bdeb12u1?arch=source&distro=debian-12",
			},
		},
		{
			name: "from dpkg with source version",
			input: pkg.Package{
				Name:    "attr",
				Version: "1:2.4.47-2+b1",
				Type:    pkg.DebPkg,
				PURL:    "pkg:deb/debian/attr@1%3A2.4.47-2%2Bb1?arch=amd64&distro=debian-12&upstream=attr%401%3A2.4.47-2",
				Metadata: pkg.DpkgDBEntry{
					Package:       "attr",
					Version:       "1:2.4.47-2+b1",
					Source:        "attr",
					SourceVersion: "1:2.4.47-2",
					Architecture:  "amd64",
				},
			},
			expected: &cyclonedx.ExternalReference{
				Type: cyclonedx.ERTypeSourceDistribution, URL: "pkg:deb/debian/attr@1%3A2.4.47-2?arch=source&distro=debian-12",
			},
		},
		{
			name: "from rpm",
			input: pkg.Package{
				Name:    "bind-export-libs",
				Version: "32:9.11.13-3.el8",
				Type:    pkg.RpmPkg,
				PURL:    "pkg:rpm/centos/bind-export-libs@9.11.13-3.el8?arch=x86_64&distro=centos-8&epoch=32&upstream=bind-9.11.13-3.el8.src.rpm",
				Metadata: pkg.RpmDBEntry{
					Name:      "bind-export-libs",
					Version:   "9.11.13",
					Release:   "3.el8",
					Epoch:     &rpm_epoch,
					Arch:      "x86_64",
					SourceRpm: "bind-9.11.13-3.el8.src.rpm",
				},
			},
			expected: &cyclonedx.ExternalReference{
				Type: cyclonedx.ERTypeSourceDistribution, URL: "pkg:rpm/centos/bind@9.11.13-3.el8?arch=source&distro=centos-8&epoch=32",
			},
		},
		{
			name: "from alpm",
			input: pkg.Package{
				Name:    "gcc-libs",
				Version: "13.2.1-3",
				Type:    pkg.AlpmPkg,
				PURL:    "pkg:alpm/arch/gcc-libs@13.2.1-3?arch=x86_64&distro=arch-rolling&upstream=gcc",
				Metadata: pkg.AlpmDBEntry{
					Package:      "gcc-libs",
					Version:      "13.2.1-3",
					BasePackage:  "gcc",
					Architecture: "x86_64",
				},
			},
			expected: &cyclonedx.ExternalReference{
				Type: cyclonedx.ERTypeSourceDistribution, URL: "pkg:alpm/arch/gcc@13.2.1-3?arch=source&distro=arch-rolling",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeSourcePackageExternalReference(test.input))
		})
	}
}

func Test_isValidExternalRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid URL for external_reference, git protocol",
			input:    "git+https://github.com/abc/def.git",
			expected: true,
		},
		{
			name:     "valid URL for external_reference, git protocol",
			input:    "git+https://github.com/abc/def.git",
			expected: true,
		},
		{
			name:     "invalid URL for external_reference",
			input:    "abc/def",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isValidExternalRef(test.input))
		})
	}
}

func Test_toCycloneDXAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected cyclonedx.HashAlgorithm
	}{
		{
			name:     "valid algorithm name in upper case",
			input:    "SHA1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
		{
			name:     "valid algorithm name in lower case",
			input:    "sha1",
			expected: cyclonedx.HashAlgorithm("SHA-1"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, toCycloneDXAlgorithm(test.input))
		})
	}
}
