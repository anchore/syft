package packages

import (
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/presenter/packages/model/spdx22"
	"github.com/anchore/syft/syft/pkg"
)

func Test_getSPDXExternalRefs(t *testing.T) {
	testCPE := must(pkg.NewCPE("cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*"))
	tests := []struct {
		name     string
		input    pkg.Package
		expected []spdx22.ExternalRef
	}{
		{
			name: "cpe + purl",
			input: pkg.Package{
				CPEs: []pkg.CPE{
					testCPE,
				},
				PURL: "a-purl",
			},
			expected: []spdx22.ExternalRef{
				{
					ReferenceCategory: spdx22.SecurityReferenceCategory,
					ReferenceLocator:  testCPE.BindToFmtString(),
					ReferenceType:     spdx22.Cpe23ExternalRefType,
				},
				{
					ReferenceCategory: spdx22.PackageManagerReferenceCategory,
					ReferenceLocator:  "a-purl",
					ReferenceType:     spdx22.PurlExternalRefType,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, getSPDXExternalRefs(&test.input))
		})
	}
}

func Test_getSPDXLicense(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no licenses",
			input:    pkg.Package{},
			expected: "NONE",
		},
		{
			name: "no SPDX licenses",
			input: pkg.Package{
				Licenses: []string{
					"made-up",
				},
			},
			expected: "NOASSERTION",
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: []string{
					"MIT",
				},
			},
			expected: "MIT",
		},
		{
			name: "with SPDX license expression",
			input: pkg.Package{
				Licenses: []string{
					"MIT",
					"GPL-3.0",
				},
			},
			expected: "MIT AND GPL-3.0",
		},
		{
			name: "cap insensitive",
			input: pkg.Package{
				Licenses: []string{
					"gpl-3.0",
				},
			},
			expected: "GPL-3.0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getSPDXLicense(&test.input))
		})
	}
}

func Test_noneIfEmpty(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "non-zero value",
			value:    "something",
			expected: "something",
		},
		{
			name:     "empty",
			value:    "",
			expected: "NONE",
		},
		{
			name:     "space",
			value:    " ",
			expected: "NONE",
		},
		{
			name:     "tab",
			value:    "\t",
			expected: "NONE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, noneIfEmpty(test.value))
		})
	}
}

func Test_getSPDXDownloadLocation(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "NOASSERTION",
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					URL: "",
				},
			},
			expected: "NONE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getSPDXDownloadLocation(&test.input))
		})
	}
}

func Test_getSPDXHomepage(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.GemMetadata{
					Homepage: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Homepage: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Homepage: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getSPDXHomepage(&test.input))
		})
	}
}

func Test_getSPDXSourceInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected []string
	}{
		{
			name: "locations are captured",
			input: pkg.Package{
				// note: no type given
				Locations: []source.Location{
					{
						RealPath:    "/a-place",
						VirtualPath: "/b-place",
					},
					{
						RealPath:    "/c-place",
						VirtualPath: "/d-place",
					},
				},
			},
			expected: []string{
				"from the following paths",
				"/a-place",
				"/c-place",
			},
		},
		{
			// note: no specific support for this
			input: pkg.Package{
				Type: pkg.KbPkg,
			},
			expected: []string{
				"from the following paths",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.RpmPkg,
			},
			expected: []string{
				"from RPM DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.ApkPkg,
			},
			expected: []string{
				"from APK DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.DebPkg,
			},
			expected: []string{
				"from DPKG DB",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.NpmPkg,
			},
			expected: []string{
				"from installed node module manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.PythonPkg,
			},
			expected: []string{
				"from installed python package manifest file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.JavaPkg,
			},
			expected: []string{
				"from installed java archive",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"from installed java archive",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GemPkg,
			},
			expected: []string{
				"from installed gem metadata file",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.GoModulePkg,
			},
			expected: []string{
				"from go module information",
			},
		},
		{
			input: pkg.Package{
				Type: pkg.RustPkg,
			},
			expected: []string{
				"from rust cargo manifest",
			},
		},
	}
	var pkgTypes []pkg.Type
	for _, test := range tests {
		t.Run(test.name+" "+string(test.input.Type), func(t *testing.T) {
			if test.input.Type != "" {
				pkgTypes = append(pkgTypes, test.input.Type)
			}
			actual := getSPDXSourceInfo(&test.input)
			for _, expected := range test.expected {
				assert.Contains(t, actual, expected)
			}
		})
	}
	assert.ElementsMatch(t, pkg.AllPkgs, pkgTypes, "missing one or more package types to test against (maybe a package type was added?)")
}

func Test_getSPDXOriginator(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.GemMetadata{
					Authors: []string{
						"auth1",
						"auth2",
					},
				},
			},
			expected: "auth1",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Author: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Maintainer: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from python - just name",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					Author: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from python - just email",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					AuthorEmail: "auth@auth.gov",
				},
			},
			expected: "auth@auth.gov",
		},
		{
			name: "from python - both name and email",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					Author:      "auth",
					AuthorEmail: "auth@auth.gov",
				},
			},
			expected: "auth <auth@auth.gov>",
		},
		{
			name: "from rpm",
			input: pkg.Package{
				Metadata: pkg.RpmdbMetadata{
					Vendor: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				Metadata: pkg.DpkgMetadata{
					Maintainer: "auth",
				},
			},
			expected: "auth",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Author: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getSPDXOriginator(&test.input))
		})
	}
}

func Test_getSPDXDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Homepage: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getSPDXDescription(&test.input))
		})
	}
}
