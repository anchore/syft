package licenses

import (
	"testing"
)

func Test_IsLicenseFile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// positive cases (should be detected as license files)
		{"plain LICENSE", "LICENSE", true},
		{"lowercase license", "license", true},
		{"license with extension", "LICENSE.txt", true},
		{"mixed case", "LiCeNsE", true},
		{"copying", "COPYING", true},
		{"AL2.0", "AL2.0", true},
		{"notice", "NOTICE", true},
		{"mit-license", "MIT-License", true},
		{"unlicense", "UNLICENSE", true},
		{"licence variant", "LICENCE", true},
		{"license markdown", "license.md", true},

		// negative cases (should NOT be detected)
		{"AL1.0", "AL1.0", false},
		{"readme", "README", false},
		{"readme with ext", "README.md", false},
		{"not a license", "not_a_license", false},
		{"licensor (prefix-like but not)", "LICENSOR", false},
		{"too short (below minLength)", "a", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsLicenseFile(tt.input)
			if got != tt.want {
				t.Fatalf("IsLicenseFile(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
