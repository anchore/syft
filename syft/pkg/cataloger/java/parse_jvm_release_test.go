package java

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func TestJvmCpes(t *testing.T) {
	tests := []struct {
		name           string
		pkgVersion     string
		legacyVersion  string
		primaryVendor  string
		primaryProduct string
		imageType      string
		hasJdk         bool
		expected       []cpe.CPE
	}{
		{
			name:           "zulu release",
			pkgVersion:     "9.0.1+20",
			legacyVersion:  "",
			primaryVendor:  "azul",
			primaryProduct: "zulu",
			imageType:      "jdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "azul",
						Product: "zulu",
						Version: "9.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "9.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "sun release",
			pkgVersion:     "1.6.0_322-b002",
			legacyVersion:  "",
			primaryVendor:  "sun",
			primaryProduct: "jre",
			imageType:      "jre",
			hasJdk:         true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "sun",
						Product: "jre",
						Version: "1.6.0",
						Update:  "update322",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "sun",
						Product: "jdk",
						Version: "1.6.0",
						Update:  "update322",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "oracle se release",
			pkgVersion:     "8.0.1+2",
			legacyVersion:  "1.8.0_322-b02",
			primaryVendor:  "oracle",
			primaryProduct: "java_se",
			imageType:      "jdk",
			hasJdk:         true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "java_se",
						Version: "8.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jre",
						Version: "8.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jdk",
						Version: "8.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "java_se",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jre",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.GeneratedSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jdk",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "JEP 223 version with build info",
			pkgVersion:     "9.0.1+20",
			legacyVersion:  "",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "9.0.1",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "JEP 223 version without build info",
			pkgVersion:     "11.0.9",
			legacyVersion:  "",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "11.0.9",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "no plus sign in version string",
			pkgVersion:     "1.8.0",
			legacyVersion:  "",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "1.8.0",
						Update:  "",
					},
					Source: cpe.GeneratedSource,
				},
			},
		},
		{
			name:           "empty version string",
			pkgVersion:     "",
			legacyVersion:  "",
			primaryVendor:  "oracle",
			primaryProduct: "",
			imageType:      "",
			expected:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jvmCpes(tt.pkgVersion, tt.legacyVersion, tt.primaryVendor, tt.primaryProduct, tt.imageType, tt.hasJdk)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJvmVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    *pkg.JavaVMRelease
		expected string
	}{
		{
			name: "SemanticVersion available",
			input: &pkg.JavaVMRelease{
				SemanticVersion:    "21.0.4+7",
				FullVersion:        "bogus",
				JavaVersion:        "bogus",
				JavaRuntimeVersion: "bogus",
			},
			expected: "21.0.4+7",
		},
		{
			name: "FullVersion fallback",
			input: &pkg.JavaVMRelease{
				FullVersion:        "21.0.4+7-LTS",
				JavaVersion:        "bogus",
				JavaRuntimeVersion: "bogus",
			},
			expected: "21.0.4+7-LTS",
		},
		{
			name: "JavaRuntimeVersion fallback",
			input: &pkg.JavaVMRelease{
				JavaRuntimeVersion: "21.0.4+7-LTS",
				JavaVersion:        "bogus",
			},
			expected: "21.0.4+7-LTS",
		},
		{
			name: "JavaVersion fallback",
			input: &pkg.JavaVMRelease{
				JavaVersion: "21.0.4",
			},
			expected: "21.0.4",
		},
		{
			name: "non-legacy version",
			input: &pkg.JavaVMRelease{
				JavaVersion: "11.0.11",
			},
			expected: "11.0.11",
		},
		{
			name:     "empty input fields",
			input:    &pkg.JavaVMRelease{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jvmPackageVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMajorVersion(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		expectedMajor int
	}{
		{
			name:          "valid version with major and minor",
			version:       "1.8",
			expectedMajor: 1,
		},
		{
			name:          "valid version with only major",
			version:       "11",
			expectedMajor: 11,
		},
		{
			name:          "invalid version format",
			version:       "not-a-version",
			expectedMajor: -1,
		},
		{
			name:          "empty string",
			version:       "",
			expectedMajor: -1,
		},
		{
			name:          "extra segments in version",
			version:       "1.8.0",
			expectedMajor: 1,
		},
		{
			name:          "non-numeric major",
			version:       "a.8",
			expectedMajor: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major := getMajorVersion(tt.version)
			assert.Equal(t, tt.expectedMajor, major)

		})
	}
}

func TestGetJVMVersionAndUpdate(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedVer    string
		expectedUpdate string
	}{
		{
			name:           "legacy version with underscore and build",
			version:        "1.8.0_302-b08",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "legacy version with underscore but no build",
			version:        "1.8.0_302",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "JEP 223 version with plus sign",
			version:        "9.0.1+20",
			expectedVer:    "9.0.1",
			expectedUpdate: "",
		},
		{
			name:           "JEP 223 version with plus but no update",
			version:        "11.0.9+",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "modern version without plus or underscore",
			version:        "11.0.9",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "legacy version without underscore or plus",
			version:        "1.7.0",
			expectedVer:    "1.7.0",
			expectedUpdate: "",
		},
		{
			name:           "empty version string",
			version:        "",
			expectedVer:    "",
			expectedUpdate: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, update := getJVMVersionAndUpdate(tt.version)
			assert.Equal(t, tt.expectedVer, ver)
			assert.Equal(t, tt.expectedUpdate, update)
		})
	}
}

func TestJvmPrimaryVendorProduct(t *testing.T) {
	tests := []struct {
		name            string
		implementor     string
		path            string
		imageType       string
		hasJdk          bool
		expectedVendor  string
		expectedProduct string
	}{
		{
			name:            "Azul implementor with Zulu in path",
			implementor:     "Azul Systems",
			path:            "/usr/lib/jvm/zulu-11-amd64/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "azul",
			expectedProduct: "zulu",
		},
		{
			name:            "Sun implementor with JDK",
			implementor:     "Sun Microsystems",
			path:            "/usr/lib/jvm/jdk-1.8-sun-amd64/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "sun",
			expectedProduct: "jdk",
		},
		{
			name:            "Oracle implementor with JRE",
			implementor:     "Oracle Corporation",
			path:            "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			imageType:       "JRE",
			hasJdk:          false,
			expectedVendor:  "oracle",
			expectedProduct: "jre",
		},
		{
			name:            "Oracle vendor with JDK in path",
			implementor:     "",
			path:            "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "oracle",
			expectedProduct: "jdk",
		},
		{
			name:            "OpenJDK with JDK",
			implementor:     "OpenJDK",
			path:            "/opt/java/openjdk/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "oracle", // like temurin
			expectedProduct: "openjdk",
		},
		{
			name:            "Amazon Corretto with JDK",
			implementor:     "Amazon Corretto",
			path:            "/usr/lib/jvm/java-17-amazon-corretto/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "oracle", // corretto upstream is oracle openjdk
			expectedProduct: "openjdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product := jvmPrimaryVendorProduct(tt.implementor, tt.path, tt.imageType, tt.hasJdk)
			assert.Equal(t, tt.expectedVendor, vendor)
			assert.Equal(t, tt.expectedProduct, product)
		})
	}
}

func TestJvmPurl(t *testing.T) {
	tests := []struct {
		name         string
		ri           pkg.JavaVMRelease
		version      string
		vendor       string
		product      string
		expectedPURL string
	}{
		{
			name: "build source repo provided",
			ri: pkg.JavaVMRelease{
				BuildSourceRepo: "https://github.com/adoptium/temurin-build.git",
			},
			version:      "21.0.4",
			vendor:       "oracle",
			product:      "jdk",
			expectedPURL: "pkg:generic/oracle/jdk@21.0.4?repository_url=https://github.com/adoptium/temurin-build.git",
		},
		{
			name: "source repo provided, no build source repo",
			ri: pkg.JavaVMRelease{
				SourceRepo: "https://github.com/adoptium/jdk21u.git",
			},
			version:      "21.0.4",
			vendor:       "azul",
			product:      "zulu",
			expectedPURL: "pkg:generic/azul/zulu@21.0.4?repository_url=https://github.com/adoptium/jdk21u.git",
		},
		{
			name: "no repository URLs provided",
			ri:   pkg.JavaVMRelease{
				// No repository URLs provided
			},
			version:      "17.0.2",
			vendor:       "oracle",
			product:      "jdk",
			expectedPURL: "pkg:generic/oracle/jdk@17.0.2",
		},
		{
			name: "JRE with source repo",
			ri: pkg.JavaVMRelease{
				SourceRepo: "https://github.com/adoptium/jre-repo.git",
			},
			version:      "1.8.0_302",
			vendor:       "oracle",
			product:      "jre",
			expectedPURL: "pkg:generic/oracle/jre@1.8.0_302?repository_url=https://github.com/adoptium/jre-repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPURL := jvmPurl(tt.ri, tt.version, tt.vendor, tt.product)
			assert.Equal(t, tt.expectedPURL, actualPURL)
		})
	}
}