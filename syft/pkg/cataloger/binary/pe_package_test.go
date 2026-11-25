package binary

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
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

func TestJRubyLauncherPEIsNotReportedAsJRuby(t *testing.T) {
	// Version resources of bin/jruby.exe and bin/jrubyw.exe in jruby-dist 9.4.14.0.
	// The 1.0 is the launcher's own version, not the JRuby version.
	vr := map[string]string{
		"CompanyName":      "http://www.jruby.org/",
		"FileDescription":  "Windows JRuby Launcher",
		"FileVersion":      "1.0",
		"InternalName":     "jruby.exe",
		"LegalCopyright":   "Copyright 2009-2010 JRuby Team",
		"OriginalFilename": "jruby.exe",
		"ProductName":      "JRuby",
		"ProductVersion":   "1.0",
	}

	p := newPEPackage(vr, file.NewLocation("/opt/jruby/bin/jruby.exe"))

	if p.Name != "jruby-launcher" {
		t.Fatalf("expected name %q, got %q", "jruby-launcher", p.Name)
	}
	if p.Version != "1.0" {
		t.Fatalf("expected version %q, got %q", "1.0", p.Version)
	}
	for _, c := range cpegenerate.FromPackageAttributes(p) {
		if c.Attributes.Product == "jruby" {
			t.Fatalf("launcher must not get a jruby product CPE, got %s", c.Attributes.String())
		}
	}
}

func TestJRubyNamedPEWithoutLauncherDescriptionIsUnchanged(t *testing.T) {
	vr := map[string]string{
		"ProductName":    "JRuby",
		"ProductVersion": "9.4.14.0",
	}

	p := newPEPackage(vr, file.NewLocation("/opt/jruby/bin/other.exe"))

	if p.Name != "JRuby" || p.Version != "9.4.14.0" {
		t.Fatalf("expected JRuby 9.4.14.0, got %s %s", p.Name, p.Version)
	}
}
