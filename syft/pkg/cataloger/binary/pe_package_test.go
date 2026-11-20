package binary

import (
	"slices"
	"testing"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

func TestGhostscriptPEGeneratesGenericPURL(t *testing.T) {
	vr := map[string]string{
		"CompanyName":     "Artifex Software, Inc.",
		"ProductName":     "GPL Ghostscript",
		"FileDescription": "Ghostscript Interpreter",
		"ProductVersion":  "9.54.0",
	}

	loc := file.NewLocation("/usr/bin/gswin64c.exe")
	p := newPEPackage(vr, loc)

	expected := "pkg:generic/ghostscript@9.54.0"
	if p.PURL != expected {
		t.Fatalf("expected purl %q, got %q", expected, p.PURL)
	}
}

func TestPHPExtensionPEIsNotReportedAsPHP(t *testing.T) {
	tests := []struct {
		name     string
		vr       map[string]string
		wantName string
		wantPURL string
		wantCPEs []string
	}{
		{
			name: "third-party PHP extension DLL",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"FileDescription":  "php_phpstan_turbo.dll",
				"InternalName":     "PHPSTAN_TURBO extension",
				"OriginalFilename": "php_phpstan_turbo.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.3.36",
			},
			wantName: "phpstan_turbo",
			wantPURL: "pkg:generic/phpstan_turbo@8.3.36",
			wantCPEs: []string{"cpe:2.3:a:php-phpstan_turbo:php-phpstan_turbo:8.3.36:*:*:*:*:*:*:*"},
		},
		{
			name: "bundled PHP extension DLL",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"OriginalFilename": "php_openssl.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.4.27",
			},
			wantName: "openssl",
			wantPURL: "pkg:generic/openssl@8.4.27",
			wantCPEs: []string{"cpe:2.3:a:php-openssl:php-openssl:8.4.27:*:*:*:*:*:*:*"},
		},
		{
			name: "PHP extension DLL identified by InternalName only",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"InternalName":     "PHPSTAN_TURBO_CORE extension",
				"OriginalFilename": "phpstan_turbo_core.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.3.36",
			},
			wantName: "phpstan_turbo_core",
			wantPURL: "pkg:generic/phpstan_turbo_core@8.3.36",
			wantCPEs: []string{"cpe:2.3:a:php-phpstan_turbo_core:php-phpstan_turbo_core:8.3.36:*:*:*:*:*:*:*"},
		},
		{
			name: "PECL extension DLL uses its own version from FileVersion",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"FileVersion":      "3.5.3",
				"InternalName":     "MYEXT extension",
				"OriginalFilename": "php_myext.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.4.27",
			},
			wantName: "myext",
			wantPURL: "pkg:generic/myext@3.5.3",
			wantCPEs: []string{"cpe:2.3:a:php-myext:php-myext:3.5.3:*:*:*:*:*:*:*"},
		},
		{
			name: "PHP SAPI DLL is still PHP",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"InternalName":     "PHP8APACHE2_4 SAPI",
				"OriginalFilename": "php8apache2_4.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.4.27",
			},
			wantName: "PHP",
		},
		{
			name: "PHP interpreter DLL is still PHP",
			vr: map[string]string{
				"CompanyName":      "The PHP Group",
				"InternalName":     "php",
				"OriginalFilename": "php8ts.dll",
				"ProductName":      "PHP",
				"ProductVersion":   "8.4.27",
			},
			wantName: "PHP",
		},
		{
			name: "non-PHP product with php_ filename is untouched",
			vr: map[string]string{
				"OriginalFilename": "php_helper.dll",
				"ProductName":      "Some Tool",
				"ProductVersion":   "1.0.0",
			},
			wantName: "Some Tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPEPackage(tt.vr, file.NewLocation("/some/file.dll"))
			if p.Name != tt.wantName {
				t.Errorf("name: want %q, got %q", tt.wantName, p.Name)
			}
			if p.PURL != tt.wantPURL {
				t.Errorf("purl: want %q, got %q", tt.wantPURL, p.PURL)
			}
			var gotCPEs []string
			for _, c := range p.CPEs {
				if c.Source != cpe.DeclaredSource {
					t.Errorf("cpe src: want declared, got %q", c.Source)
				}
				gotCPEs = append(gotCPEs, c.Attributes.String())
			}
			if !slices.Equal(gotCPEs, tt.wantCPEs) {
				t.Errorf("cpes: want %v, got %v", tt.wantCPEs, gotCPEs)
			}
		})
	}
}
