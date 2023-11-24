package key

import "testing"

func TestNpmPackageKey(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"lodash", "1.0.0", "lodash:1.0.0"},
		{"react", "16.8.0", "react:16.8.0"},
		{"", "1.0.0", ":1.0.0"},
		{"lodash", "", "lodash:"},
		{"", "", ":"},
	}

	for _, tt := range tests {
		t.Run(tt.name+":"+tt.version, func(t *testing.T) {
			got := NpmPackageKey(tt.name, tt.version)
			if got != tt.expected {
				t.Errorf("NpmPackageKey(%q, %q) = %q; want %q", tt.name, tt.version, got, tt.expected)
			}
		})
	}
}
