package pe

import (
	"fmt"
	"os"
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
	singleFileDepsJSON, err := os.ReadFile("testdata/net8-app-single-file.deps.json")
	require.NoError(t, err)

	tests := []struct {
		name         string
		fixture      string
		path         string
		wantVR       map[string]string
		wantCLR      bool
		wantDepsJSON string
		wantErr      require.ErrorAssertionFunc
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
			// the apphost is a native launcher, not a managed assembly, so there is no CLR evidence to find in it.
			// note the contrast with the single file deployment case below, which is the same apphost with the app
			// (and the CLRDEBUGINFO resource) bundled into it.
			name:    "apphost",
			path:    "/app/dotnetapp.exe",
			fixture: "image-net8-app",
			wantCLR: false, // important!
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
			// the framework-dependent apphost, which carries the bundle signature with a zero offset
			// placeholder because it was never published as a single file. This is the most common shape a
			// .NET executable takes, so anything it reports as a parse failure is reported against nearly
			// every .NET binary that exists.
			name:    "framework dependent apphost",
			path:    "/app/dotnetapp.exe",
			fixture: "image-net8-app",
			wantCLR: false, // the CLR metadata lives in the sibling dotnetapp.dll
			wantVR: map[string]string{
				"Assembly Version": "1.0.0.0",
				"CompanyName":      "dotnetapp",
				"FileDescription":  "dotnetapp",
				"FileVersion":      "1.0.0.0",
				"InternalName":     "dotnetapp.dll",
				"LegalCopyright":   " ",
				"OriginalFilename": "dotnetapp.dll",
				"ProductName":      "dotnetapp",
				"ProductVersion":   "1.0.0",
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
			wantDepsJSON: string(singleFileDepsJSON),
			wantErr:      require.NoError,
		},
	}

	var fixtures []string
	for _, tt := range tests {
		fixtures = append(fixtures, tt.fixture)
	}
	resolvers := fixtureResolvers(t, fixtures...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			reader := fixtureFile(t, resolvers[tt.fixture], tt.path)

			got, err := Read(reader)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			// a real binary must parse completely. ParseErr is how a partial parse reaches the unknowns
			// channel, so anything non-nil here is a field we silently failed to read on stock input.
			require.NoError(t, got.ParseErr, "a well-formed binary must not report a partial parse")

			if d := cmp.Diff(tt.wantVR, got.VersionResources); d != "" {
				t.Errorf("unexpected version resources (-want +got): %s", d)
			}

			assert.Equal(t, tt.wantCLR, got.CLR.HasEvidenceOfCLR())

			if d := cmp.Diff(tt.wantDepsJSON, got.EmbeddedDepsJSON); d != "" {
				fmt.Printf("got embedded deps.json: %s\n", got.EmbeddedDepsJSON)
				t.Errorf("unexpected deps.json location (-want +got): %s", d)
			}
		})
	}
}

// fixtureResolvers loads each distinct image fixture once, from the parent test, so that subtests reading multiple
// files out of the same image don't each pay for loading the docker archive again (which dominates the runtime of
// these tests, especially under -race).
func fixtureResolvers(t *testing.T, fixtures ...string) map[string]file.Resolver {
	resolvers := make(map[string]file.Resolver)
	for _, fixture := range fixtures {
		if _, ok := resolvers[fixture]; ok {
			continue
		}

		img := imagetest.GetFixtureImage(t, "docker-archive", fixture)

		s := stereoscopesource.New(img, stereoscopesource.ImageConfig{
			Reference: fixture,
		})

		r, err := s.FileResolver(source.SquashedScope)
		require.NoError(t, err)

		resolvers[fixture] = r
	}
	return resolvers
}

func fixtureFile(t *testing.T, r file.Resolver, path string) file.LocationReadCloser {
	locs, err := r.FilesByPath(path)
	require.NoError(t, err)

	require.Len(t, locs, 1)
	loc := locs[0]

	reader, err := r.FileContentsByLocation(loc)
	require.NoError(t, err)
	return file.NewLocationReadCloser(loc, reader)
}
