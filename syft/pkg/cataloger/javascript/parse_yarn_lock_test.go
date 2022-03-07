package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseYarnLock(t *testing.T) {
	expected := map[string]pkg.Package{
		"@babel/code-frame": {
			Name:     "@babel/code-frame",
			Version:  "7.10.4",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"@types/minimatch": {
			Name:     "@types/minimatch",
			Version:  "3.0.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"@types/qs": {
			Name:     "@types/qs",
			Version:  "6.9.4",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"ajv": {
			Name:     "ajv",
			Version:  "6.12.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"atob": {
			Name:     "atob",
			Version:  "2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"aws-sdk": {
			Name:     "aws-sdk",
			Version:  "2.706.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"jhipster-core": {
			Name:     "jhipster-core",
			Version:  "7.3.4",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"asn1.js": {
			Name:     "asn1.js",
			Version:  "4.10.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"c0n-fab_u.laTION": {
			Name:     "c0n-fab_u.laTION",
			Version:  "7.7.7",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
	}

	fixture, err := os.Open("test-fixtures/yarn/yarn.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseYarnLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse yarn.lock: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)
}

func TestParseYarnFindPackageNames(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			line:     "\"@babel/code-frame@npm:7.10.4\":",
			expected: "@babel/code-frame",
		},
		{
			line:     "\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.10.4\":",
			expected: "@babel/code-frame",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5:",
			expected: "ajv",
		},
		{
			line:     "aws-sdk@2.706.0:",
			expected: "aws-sdk",
		},
		{
			line:     "asn1.js@^4.0.0:",
			expected: "asn1.js",
		},
		{
			line:     "c0n-fab_u.laTION@^7.0.0",
			expected: "c0n-fab_u.laTION",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()
			actual := findPackageName(test.line)
			if actual != test.expected {
				t.Errorf("incorrectly parsed package name: want %s, got %s", test.expected, actual)
			}
		})
	}
}

func TestParseYarnFindPackageVersions(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			line:     "  version \"7.10.4\"",
			expected: "7.10.4",
		},
		{
			line:     " version \"7.11.5\"",
			expected: "7.11.5",
		},
		{
			line:     "version \"7.12.6\"",
			expected: "",
		},
		{
			line:     "  version \"0.0.0\"",
			expected: "0.0.0",
		},
		{
			line:     "  version \"2\" ",
			expected: "2",
		},
		{
			line:     "  version \"9.3\"",
			expected: "9.3",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5",
			expected: "",
		},
		{
			line:     "atob@^2.1.2:",
			expected: "",
		},
		{
			line:     "\"color-convert@npm:^1.9.0\":",
			expected: "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()
			actual := findPackageVersion(test.line)
			if actual != test.expected {
				t.Errorf("incorrectly parsed package name: want %s, got %s", test.expected, actual)
			}
		})
	}
}
