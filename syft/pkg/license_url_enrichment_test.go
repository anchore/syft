package pkg

import (
	"context"
	"testing"
)

func TestNewLicenseFromFieldsWithContext_URLEnrichment(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		url        string
		wantValue  string
		wantHasURL bool
	}{
		{
			name:       "Empty value with MIT URL should enrich",
			value:      "",
			url:        "http://opensource.org/licenses/MIT",
			wantValue:  "MIT",
			wantHasURL: true,
		},
		{
			name:       "Empty value with Apache URL should enrich",
			value:      "",
			url:        "https://www.apache.org/licenses/LICENSE-2.0",
			wantValue:  "Apache-2.0",
			wantHasURL: true,
		},
		{
			name:       "Non-empty value should not be overridden",
			value:      "Custom-License",
			url:        "http://opensource.org/licenses/MIT",
			wantValue:  "Custom-License",
			wantHasURL: true,
		},
		{
			name:       "Unknown URL should not enrich",
			value:      "",
			url:        "https://example.com/unknown-license",
			wantValue:  "",
			wantHasURL: true,
		},
		{
			name:       "Empty value and empty URL",
			value:      "",
			url:        "",
			wantValue:  "",
			wantHasURL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			license := NewLicenseFromFieldsWithContext(ctx, tt.value, tt.url, nil)

			if license.Value != tt.wantValue {
				t.Errorf("NewLicenseFromFieldsWithContext() Value = %v, want %v", license.Value, tt.wantValue)
			}

			hasURL := len(license.URLs) > 0
			if hasURL != tt.wantHasURL {
				t.Errorf("NewLicenseFromFieldsWithContext() has URL = %v, want %v", hasURL, tt.wantHasURL)
			}

			if tt.wantHasURL && tt.url != "" && license.URLs[0] != tt.url {
				t.Errorf("NewLicenseFromFieldsWithContext() URL = %v, want %v", license.URLs[0], tt.url)
			}
		})
	}
}

func TestLicenseBuilder_URLOnlyEnrichment(t *testing.T) {
	tests := []struct {
		name       string
		urls       []string
		wantValue  string
		wantSPDX   string
		wantHasURL bool
	}{
		{
			name:       "MIT URL only should enrich",
			urls:       []string{"http://opensource.org/licenses/MIT"},
			wantValue:  "MIT",
			wantSPDX:   "MIT",
			wantHasURL: true,
		},
		{
			name:       "Apache URL only should enrich",
			urls:       []string{"https://www.apache.org/licenses/LICENSE-2.0"},
			wantValue:  "Apache-2.0",
			wantSPDX:   "Apache-2.0",
			wantHasURL: true,
		},
		{
			name:       "Multiple URLs should use first",
			urls:       []string{"http://opensource.org/licenses/MIT", "https://example.com/other"},
			wantValue:  "MIT",
			wantSPDX:   "MIT",
			wantHasURL: true,
		},
		{
			name:       "Unknown URL should not enrich",
			urls:       []string{"https://example.com/unknown-license"},
			wantValue:  "",
			wantSPDX:   "",
			wantHasURL: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			builder := newLicenseBuilder().WithURLs(tt.urls...)
			licenses := builder.Build(ctx).ToSlice()

			if len(licenses) == 0 {
				t.Fatal("Expected at least one license")
			}

			license := licenses[0]

			if license.Value != tt.wantValue {
				t.Errorf("License Value = %v, want %v", license.Value, tt.wantValue)
			}

			if license.SPDXExpression != tt.wantSPDX {
				t.Errorf("License SPDXExpression = %v, want %v", license.SPDXExpression, tt.wantSPDX)
			}

			hasURL := len(license.URLs) > 0
			if hasURL != tt.wantHasURL {
				t.Errorf("License has URL = %v, want %v", hasURL, tt.wantHasURL)
			}

			if tt.wantHasURL && len(tt.urls) > 0 {
				if len(license.URLs) != len(tt.urls) {
					t.Errorf("License URL count = %v, want %v", len(license.URLs), len(tt.urls))
				}
				if license.URLs[0] != tt.urls[0] {
					t.Errorf("License first URL = %v, want %v", license.URLs[0], tt.urls[0])
				}
			}
		})
	}
}

func TestNewLicenseFromURLsWithContext_URLEnrichment(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		urls      []string
		wantValue string
	}{
		{
			name:      "Empty value with MIT URL should enrich via builder",
			value:     "",
			urls:      []string{"http://opensource.org/licenses/MIT"},
			wantValue: "MIT",
		},
		{
			name:      "Non-empty value should not be changed",
			value:     "Custom-License",
			urls:      []string{"http://opensource.org/licenses/MIT"},
			wantValue: "Custom-License",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			license := NewLicenseFromURLsWithContext(ctx, tt.value, tt.urls...)

			if license.Value != tt.wantValue {
				t.Errorf("NewLicenseFromURLsWithContext() Value = %v, want %v", license.Value, tt.wantValue)
			}
		})
	}
}
