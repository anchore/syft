package pe

import (
	"bytes"
	"debug/pe"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDepsJSONFromBundle_Versions(t *testing.T) {
	tests := []struct {
		name            string
		fixture         string
		path            string
		wantDepsJSON    bool   // true if deps.json should be found
		wantJSONContain string // string that should be in the JSON (varies by .NET version)
	}{
		{
			name:            "V1 bundle (.NET Core 3.1)",
			fixture:         "image-dotnet31-single-file",
			path:            "/app/hello.exe",
			wantDepsJSON:    true,
			wantJSONContain: "runtimeOptions", // .NET Core 3.1 uses runtimeOptions
		},
		{
			name:            "V2 bundle (.NET 5)",
			fixture:         "image-dotnet5-single-file",
			path:            "/app/hello.exe",
			wantDepsJSON:    true,
			wantJSONContain: "runtimeTarget", // .NET 5+ uses runtimeTarget
		},
		{
			name:            "V6 bundle (.NET 6)",
			fixture:         "image-dotnet6-single-file",
			path:            "/app/hello.exe",
			wantDepsJSON:    true,
			wantJSONContain: "runtimeTarget", // .NET 6+ uses runtimeTarget
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := fixtureFile(t, tt.fixture, tt.path)
			defer reader.Close()

			got, err := Read(reader)
			require.NoError(t, err)

			if tt.wantDepsJSON {
				assert.NotEmpty(t, got.EmbeddedDepsJSON, "expected deps.json to be extracted from bundle")
				// verify it looks like valid JSON for this .NET version
				assert.Contains(t, got.EmbeddedDepsJSON, tt.wantJSONContain, "deps.json should contain expected field")
			} else {
				assert.Empty(t, got.EmbeddedDepsJSON, "expected no deps.json in non-bundle file")
			}
		})
	}
}

// readSizeRecorder records the largest single Read length requested of it. The worst end offset PE
// headers can describe is about 8.6GB, and `make([]byte, 8.6e9)` succeeds on any 64-bit host from fresh
// anonymous mmap without touching the pages, so asserting "no panic" would pass with or without the
// bound. The requested read size is what actually distinguishes them.
type readSizeRecorder struct {
	*bytes.Reader
	maxRead int
}

func (r *readSizeRecorder) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	return r.Reader.Read(p)
}

func TestExtractDepsJSONFromBundle_MalformedSectionSizesDoNotOverAllocate(t *testing.T) {
	// PointerToRawData and SizeOfRawData are user-controlled and unrelated to the real file size
	sections := []pe.SectionHeader32{{PointerToRawData: 0xFFFFFFFF, SizeOfRawData: 0xFFFFFFFF}}

	// sanity: the headers really do describe an end offset far past the file, so the bound is what keeps
	// the allocation small rather than the input being small
	require.Greater(t, calculatePEEndOffset(sections), int64(8*1024*1024*1024))

	const fileSize = 512 // a small "file" with no bundle signature
	r := &readSizeRecorder{Reader: bytes.NewReader(make([]byte, fileSize))}

	content, err := extractDepsJSONFromBundle(r, sections)
	require.NoError(t, err)
	assert.Empty(t, content)
	assert.LessOrEqual(t, r.maxRead, fileSize,
		"the search must be bounded by the file, not by what the section headers claim")
}
