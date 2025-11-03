package binary

import (
	"testing"

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
