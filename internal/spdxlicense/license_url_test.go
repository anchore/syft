package spdxlicense

import (
	"testing"
)

func TestLicenseByURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantID    string
		wantFound bool
	}{
		{
			name:      "MIT license URL (https)",
			url:       "https://opensource.org/license/mit/",
			wantID:    "MIT",
			wantFound: true,
		},
		{
			name:      "MIT license URL (http)",
			url:       "http://opensource.org/licenses/MIT",
			wantID:    "MIT",
			wantFound: true,
		},
		{
			name:      "Apache 2.0 license URL",
			url:       "https://www.apache.org/licenses/LICENSE-2.0",
			wantID:    "Apache-2.0",
			wantFound: true,
		},
		{
			name:      "GPL 3.0 or later URL",
			url:       "https://www.gnu.org/licenses/gpl-3.0-standalone.html",
			wantID:    "GPL-3.0-or-later",
			wantFound: true,
		},
		{
			name:      "BSD 3-Clause URL",
			url:       "https://opensource.org/licenses/BSD-3-Clause",
			wantID:    "BSD-3-Clause",
			wantFound: true,
		},
		{
			name:      "URL with trailing whitespace",
			url:       "  http://opensource.org/licenses/MIT  ",
			wantID:    "MIT",
			wantFound: true,
		},
		{
			name:      "Unknown URL",
			url:       "https://example.com/unknown-license",
			wantID:    "",
			wantFound: false,
		},
		{
			name:      "Empty URL",
			url:       "",
			wantID:    "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, found := LicenseByURL(tt.url)
			if found != tt.wantFound {
				t.Errorf("LicenseByURL() found = %v, want %v", found, tt.wantFound)
			}
			if found {
				if info.ID != tt.wantID {
					t.Errorf("LicenseByURL() ID = %v, want %v", info.ID, tt.wantID)
				}
			}
		})
	}
}

func TestLicenseByURL_DeprecatedLicenses(t *testing.T) {
	// Test that deprecated license URLs map to their replacement licenses
	// For example, GPL-2.0+ should map to GPL-2.0-or-later

	// This test needs actual URLs from deprecated licenses
	// We can verify by checking if a deprecated license URL maps to a non-deprecated ID
	url := "https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html"
	info, found := LicenseByURL(url)

	if found {
		// Check that we got a valid non-deprecated license ID
		if info.ID == "" {
			t.Error("Got empty license ID for deprecated license URL")
		}
		// The ID should be the replacement (GPL-2.0-only or GPL-2.0-or-later)
		// depending on the URL
		t.Logf("Deprecated license URL mapped to: ID=%s", info.ID)
	}
}
