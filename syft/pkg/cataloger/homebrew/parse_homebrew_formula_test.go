package homebrew

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ParseHomebrewPackage(t *testing.T) {

	tests := []struct {
		name     string
		fixture  string
		expected pkg.Package
	}{
		{
			name:    "syft tap",
			fixture: "test-fixtures/formulas/syft/1.23.1/.brew/syft.rb",
			expected: pkg.Package{
				Name:    "syft",
				Version: "1.23.1",
				Type:    pkg.HomebrewPkg,
				Locations: file.NewLocationSet(
					file.NewLocation("test-fixtures/formulas/syft/1.23.1/.brew/syft.rb").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				),
				Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValues("Apache License 2.0")...),
				FoundBy:  "homebrew-cataloger",
				PURL:     "pkg:brew/syft@1.23.1",
				Metadata: pkg.HomebrewFormula{
					Homepage:    "https://github.com/anchore/syft",
					Description: "A tool that generates a Software Bill Of Materials (SBOM) from container images and filesystems",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, test.fixture, parseHomebrewFormula, []pkg.Package{test.expected}, nil)
		})
	}
}

func TestGetTapFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "valid path",
			path:     "/opt/homebrew/Library/Taps/testorg/sometap/Formula/bar.rb",
			expected: "testorg/sometap",
		},
		{
			name:     "valid path with different prefix",
			path:     "/usr/local/Library/Taps/otherorg/anothertap/Formula/foo.rb",
			expected: "otherorg/anothertap",
		},
		{
			name:     "missing Library/Taps",
			path:     "/opt/homebrew/Cellar/formula.rb",
			expected: "",
		},
		{
			name:     "incomplete path after Taps",
			path:     "/opt/homebrew/Library/Taps/testorg",
			expected: "",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTapFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("getTapFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetQuotedValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple quoted string",
			input:    "\"hello\"",
			expected: "hello",
		},
		{
			name:     "quoted string with whitespace outside",
			input:    "  \"hello world\"  ",
			expected: "hello world",
		},
		{
			name:     "quoted string with content before and after",
			input:    "prefix \"extracted value\" suffix",
			expected: "extracted value",
		},
		{
			name:     "multiple quotes - extract first to last",
			input:    "\"first\" something \"last\"",
			expected: "first\" something \"last",
		},
		{
			name:     "nested quotes",
			input:    "\"outer \"inner\" outer\"",
			expected: "outer \"inner\" outer",
		},
		{
			name:     "empty quoted string",
			input:    "\"\"",
			expected: "",
		},
		{
			name:     "only opening quote",
			input:    "\"unbalanced",
			expected: "",
		},
		{
			name:     "only closing quote",
			input:    "unbalanced\"",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: "",
		},
		{
			name:     "no quotes",
			input:    "hello world",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getQuotedValue(tt.input)
			if result != tt.expected {
				t.Errorf("getQuotedValue(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
