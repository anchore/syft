package binary

import (
	"testing"

	"github.com/stretchr/testify/assert"

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

func Test_findVersionFromVR(t *testing.T) {
	tests := []struct {
		name             string
		versionResources map[string]string
		want             string
	}{
		{
			name:             "dotted version is kept as-is",
			versionResources: map[string]string{"ProductVersion": "3.0.21.0"},
			want:             "3.0.21.0",
		},
		{
			name: "comma separated version is normalized",
			// VERSIONINFO resources often mirror the .rc FILEVERSION 3,0,21,0 form
			versionResources: map[string]string{"ProductVersion": "3, 0, 21, 0"},
			want:             "3.0.21.0",
		},
		{
			name:             "comma separated version without spaces is normalized",
			versionResources: map[string]string{"FileVersion": "3,0,21,0"},
			want:             "3.0.21.0",
		},
		{
			name:             "version with trailing comment is unaffected",
			versionResources: map[string]string{"ProductVersion": "1.2.3 (build 456)"},
			want:             "1.2.3",
		},
		{
			name:             "non numeric comma separated value is kept as-is",
			versionResources: map[string]string{"ProductVersion": "1.0, beta"},
			want:             "1.0,",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, findVersionFromVR(tt.versionResources))
		})
	}
}
