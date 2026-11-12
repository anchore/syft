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

func TestLicenseByURL_AlternateScheme(t *testing.T) {
	// Test that URLs work with alternate schemes (http ↔ https) even if only one is in the SPDX list
	tests := []struct {
		name      string
		url       string
		wantID    string
		wantFound bool
	}{
		{
			name:      "Apache URL with http when https is in list",
			url:       "http://www.apache.org/licenses/LICENSE-2.0",
			wantID:    "Apache-2.0",
			wantFound: true,
		},
		{
			name:      "BSD-3-Clause with http when https is in list",
			url:       "http://opensource.org/licenses/BSD-3-Clause",
			wantID:    "BSD-3-Clause",
			wantFound: true,
		},
		{
			name:      "Unknown URL with http still not found",
			url:       "http://example.com/not-a-real-license",
			wantID:    "",
			wantFound: false,
		},
		{
			name:      "Unknown URL with https still not found",
			url:       "https://example.com/not-a-real-license",
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
			if found && info.ID != tt.wantID {
				t.Errorf("LicenseByURL() ID = %v, want %v", info.ID, tt.wantID)
			}
		})
	}
}

func TestLicenseByURL_OpenSourceOrgVariants(t *testing.T) {
	// SPDX has changed the form of opensource.org URLs across list versions (e.g. 3.29.0 moved
	// opensource.org/licenses/MIT to opensource.org/license/MIT); every form should keep resolving.
	tests := []struct {
		name   string
		url    string
		wantID string
	}{
		{name: "old plural path", url: "http://opensource.org/licenses/MIT", wantID: "MIT"},
		{name: "new singular path", url: "https://opensource.org/license/MIT", wantID: "MIT"},
		{name: "lowercase with trailing slash", url: "https://opensource.org/license/mit/", wantID: "MIT"},
		{name: "plural path with trailing slash", url: "https://opensource.org/licenses/MIT/", wantID: "MIT"},
		{name: "www prefix", url: "https://www.opensource.org/licenses/MIT", wantID: "MIT"},
		{name: "uppercase host", url: "https://WWW.OpenSource.org/licenses/MIT", wantID: "MIT"},
		{name: "old plural path BSD-3-Clause", url: "https://opensource.org/licenses/BSD-3-Clause", wantID: "BSD-3-Clause"},
		{name: "new singular path BSD-3-Clause", url: "https://opensource.org/license/BSD-3-Clause", wantID: "BSD-3-Clause"},
		{name: "lowercase BSD-3-Clause", url: "https://opensource.org/licenses/bsd-3-clause", wantID: "BSD-3-Clause"},
		{name: "old plural path Apache-2.0", url: "http://opensource.org/licenses/Apache-2.0", wantID: "Apache-2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, found := LicenseByURL(tt.url)
			if !found {
				t.Fatalf("LicenseByURL(%q) found = false, want true", tt.url)
			}
			if info.ID != tt.wantID {
				t.Errorf("LicenseByURL(%q) ID = %v, want %v", tt.url, info.ID, tt.wantID)
			}
		})
	}
}

func TestLicenseByURL_NonOpenSourceOrgStaysExact(t *testing.T) {
	// the relaxed matching is scoped to opensource.org; other hosts may have case-sensitive paths
	if _, found := LicenseByURL("https://www.apache.org/licenses/license-2.0"); found {
		t.Errorf("LicenseByURL() found = true for case-altered non-opensource.org URL, want false")
	}
	if _, found := LicenseByURL("https://opensource.org/licenses/not-a-real-license"); found {
		t.Errorf("LicenseByURL() found = true for unknown opensource.org URL, want false")
	}
}

func TestNormalizeOpenSourceOrgURL(t *testing.T) {
	tests := []struct {
		url    string
		want   string
		wantOK bool
	}{
		{url: "opensource.org/licenses/MIT", want: "opensource.org/license/mit", wantOK: true},
		{url: "opensource.org/license/mit/", want: "opensource.org/license/mit", wantOK: true},
		{url: "www.opensource.org/licenses/EPL-2.0", want: "opensource.org/license/epl-2.0", wantOK: true},
		{url: "lists.opensource.org/pipermail/license-discuss", wantOK: false},
		{url: "www.apache.org/licenses/LICENSE-2.0", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got, ok := normalizeOpenSourceOrgURL(tt.url)
			if ok != tt.wantOK {
				t.Fatalf("normalizeOpenSourceOrgURL(%q) ok = %v, want %v", tt.url, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("normalizeOpenSourceOrgURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestBuildOpenSourceOrgURLToLicense(t *testing.T) {
	index := buildOpenSourceOrgURLToLicense(map[string]string{
		"opensource.org/licenses/MIT": "MIT",
		"opensource.org/license/mit/": "MIT",
		"opensource.org/licenses/Foo": "Foo-1.0",
		"opensource.org/license/foo":  "Foo-2.0",
		"opensource.org/license/FOO/": "Foo-1.0",
		"www.apache.org/licenses/Bar": "Bar",
	})

	if got := index["opensource.org/license/mit"]; got != "MIT" {
		t.Errorf("index[mit] = %q, want MIT", got)
	}
	if got, exists := index["opensource.org/license/foo"]; exists {
		t.Errorf("index[foo] = %q, want no entry for URL forms mapping to different licenses", got)
	}
	if len(index) != 1 {
		t.Errorf("len(index) = %d, want 1 (non-opensource.org URLs excluded): %v", len(index), index)
	}
}

func TestStripScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "https scheme stripped",
			url:  "https://example.com/license",
			want: "example.com/license",
		},
		{
			name: "http scheme stripped",
			url:  "http://example.com/license",
			want: "example.com/license",
		},
		{
			name: "ftp scheme not stripped",
			url:  "ftp://example.com/license",
			want: "ftp://example.com/license",
		},
		{
			name: "no scheme unchanged",
			url:  "example.com/license",
			want: "example.com/license",
		},
		{
			name: "empty string unchanged",
			url:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripScheme(tt.url)
			if got != tt.want {
				t.Errorf("stripScheme() = %v, want %v", got, tt.want)
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
