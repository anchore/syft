package pe

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func Test_Read_DotNetDetection(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		path    string
		wantVR  map[string]string
		wantCLR bool
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "newtonsoft",
			path:    "/app/Newtonsoft.Json.dll",
			fixture: "image-net8-app",
			wantCLR: true,
			wantVR: map[string]string{
				// the numbers are the field parse order, which helped for debugging and understanding corrupted fields
				"Comments":         "Json.NET is a popular high-performance JSON framework for .NET", // 1
				"CompanyName":      "Newtonsoft",                                                     // 2
				"FileDescription":  "Json.NET .NET 6.0",                                              // 3
				"FileVersion":      "13.0.3.27908",                                                   // 4
				"InternalName":     "Newtonsoft.Json.dll",                                            // 5
				"LegalCopyright":   "Copyright © James Newton-King 2008",                             // 6
				"LegalTrademarks":  "",                                                               // 7 (empty value actually exists in the string table)
				"OriginalFilename": "Newtonsoft.Json.dll",                                            // 8
				"ProductName":      "Json.NET",                                                       // 9
				"ProductVersion":   "13.0.3+0a2e291c0d9c0c7675d445703e51750363a549ef",                // 10
				"Assembly Version": "13.0.0.0",                                                       // 11
			},
		},
		{
			name:    "humanizer",
			path:    "/app/Humanizer.dll",
			fixture: "image-net8-app",
			wantCLR: true,
			wantVR: map[string]string{
				"Comments":         "A micro-framework that turns your normal strings, type names, enum fields, date fields ETC into a human friendly format",
				"CompanyName":      "Mehdi Khalili, Claire Novotny",
				"FileDescription":  "Humanizer",
				"FileVersion":      "2.14.1.48190",
				"InternalName":     "Humanizer.dll",
				"LegalCopyright":   "Copyright © .NET Foundation and Contributors",
				"OriginalFilename": "Humanizer.dll",
				"ProductName":      "Humanizer (net6.0)",
				"ProductVersion":   "2.14.1+3ebc38de58",
				"Assembly Version": "2.14.0.0",
			},
			wantErr: require.NoError,
		},
		{
			name:    "dotnetapp",
			path:    "/app/dotnetapp.dll",
			fixture: "image-net8-app",
			wantCLR: true,
			wantVR: map[string]string{
				"CompanyName":      "dotnetapp",
				"FileDescription":  "dotnetapp",
				"FileVersion":      "1.0.0.0",
				"InternalName":     "dotnetapp.dll",
				"LegalCopyright":   " ",
				"OriginalFilename": "dotnetapp.dll",
				"ProductName":      "dotnetapp",
				"ProductVersion":   "1.0.0",
				"Assembly Version": "1.0.0.0",
			},
			wantErr: require.NoError,
		},
		{
			name:    "jruby",
			path:    "/app/jruby_windows_9_3_15_0.exe",
			fixture: "image-net8-app",
			wantCLR: false, // important!
			wantVR: map[string]string{
				"CompanyName":      "JRuby Dev Team",
				"FileDescription":  "JRuby",
				"FileVersion":      "9.3.15.0",
				"InternalName":     "jruby",
				"LegalCopyright":   "JRuby Dev Team",
				"OriginalFilename": "jruby_windows-x32_9_3_15_0.exe",
				"ProductName":      "JRuby",
				"ProductVersion":   "9.3.15.0",
			},
			wantErr: require.NoError,
		},
		{
			name:    "single file deployment",
			path:    "/app/dotnetapp.exe",
			fixture: "image-net8-app-single-file",
			// single file deployment does not have CLR metadata embedded in the COM descriptor. Instead we need
			// to look for evidence of the CLR in other resources directory names, specifically for "CLRDEBUGINFO".
			wantCLR: true,
			wantVR: map[string]string{
				"CompanyName":      "dotnetapp",
				"FileDescription":  "dotnetapp",
				"FileVersion":      "1.0.0.0",
				"InternalName":     "dotnetapp.dll",
				"LegalCopyright":   " ",
				"OriginalFilename": "dotnetapp.dll",
				"ProductName":      "dotnetapp",
				"ProductVersion":   "1.0.0",
				"Assembly Version": "1.0.0.0",
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			reader := fixtureFile(t, tt.fixture, tt.path)

			got, err := Read(reader)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			if d := cmp.Diff(tt.wantVR, got.VersionResources); d != "" {
				t.Errorf("unexpected version resources (-want +got): %s", d)
			}

			assert.Equal(t, tt.wantCLR, got.CLR.HasEvidenceOfCLR())
		})
	}
}

func fixtureFile(t *testing.T, fixture, path string) file.LocationReadCloser {
	img := imagetest.GetFixtureImage(t, "docker-archive", fixture)

	s := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: fixture,
	})

	r, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	locs, err := r.FilesByPath(path)
	require.NoError(t, err)

	require.Len(t, locs, 1)
	loc := locs[0]

	reader, err := r.FileContentsByLocation(loc)
	require.NoError(t, err)
	return file.NewLocationReadCloser(loc, reader)
}
