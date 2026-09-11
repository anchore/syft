package pe

import (
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
		wantJSONContain string // a string unique to the deps.json (and not the runtimeconfig.json) of this fixture
	}{
		{
			name:         "V1 bundle (.NET Core 3.1)",
			fixture:      "image-dotnet31-single-file",
			path:         "/app/hello.exe",
			wantDepsJSON: true,
			wantJSONContain: `"runtimeTarget": {
    "name": ".NETCoreApp,Version=v3.1/win-x64"`,
		},
		{
			name:         "V2 bundle (.NET 5)",
			fixture:      "image-dotnet5-single-file",
			path:         "/app/hello.exe",
			wantDepsJSON: true,
			wantJSONContain: `"runtimeTarget": {
    "name": ".NETCoreApp,Version=v5.0/win-x64"`,
		},
		{
			name:         "V6 bundle (.NET 6)",
			fixture:      "image-dotnet6-single-file",
			path:         "/app/hello.exe",
			wantDepsJSON: true,
			wantJSONContain: `"runtimeTarget": {
    "name": ".NETCoreApp,Version=v6.0/win-x64"`,
		},
	}

	var fixtures []string
	for _, tt := range tests {
		fixtures = append(fixtures, tt.fixture)
	}
	resolvers := fixtureResolvers(t, fixtures...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := fixtureFile(t, resolvers[tt.fixture], tt.path)
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
