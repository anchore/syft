package file

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
)

func TestLocation_ID(t *testing.T) {
	tests := []struct {
		name        string
		coordinates Coordinates
		virtualPath string
		ref         file.Reference
	}{
		{
			name: "coordinates should match location hash",
			coordinates: Coordinates{
				RealPath:     "path!",
				FileSystemID: "filesystem!",
			},
		},
		{
			name: "coordinates should match location hash (with extra fields)",
			coordinates: Coordinates{
				RealPath:     "path!",
				FileSystemID: "filesystem!",
			},
			virtualPath: "virtualPath!",
			ref: file.Reference{
				RealPath: "other-real-path!",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := Location{
				LocationData: LocationData{
					Coordinates: test.coordinates,
					AccessPath:  test.virtualPath,
					ref:         test.ref,
				},
			}
			assert.Equal(t, l.ID(), test.coordinates.ID())
		})
	}

}

func TestLocation_fullPathIsIdentity(t *testing.T) {
	a := NewLocationFromCoordinates(Coordinates{RealPath: "/a.jar", FullPath: "/a.jar!/META-INF/MANIFEST.MF"})
	b := NewLocationFromCoordinates(Coordinates{RealPath: "/b.jar", FullPath: "/b.jar!/META-INF/MANIFEST.MF"})

	assert.False(t, a.Equals(b))
	assert.NotEqual(t, a.String(), b.String())
	assert.Contains(t, a.String(), `RealPath="/a.jar"`)
}

func TestLocation_JSON(t *testing.T) {
	tests := []struct {
		name     string
		location Location
		expected string
	}{
		{
			name:     "a file outside an archive writes no fullPath",
			location: NewVirtualLocationFromDirectory("/etc/os-release", "/etc/link", file.Reference{}).WithAnnotation("k", "v"),
			expected: `{"path":"/etc/os-release","accessPath":"/etc/link","annotations":{"k":"v"}}`,
		},
		{
			name:     "a file within an archive writes its full path",
			location: NewLocationFromCoordinates(Coordinates{RealPath: "/app.war", FileSystemID: "layer", FullPath: "/app.war!/META-INF/MANIFEST.MF"}),
			expected: `{"path":"/app.war","layerID":"layer","fullPath":"/app.war!/META-INF/MANIFEST.MF","accessPath":"/app.war!/META-INF/MANIFEST.MF"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.location)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(data))

			var decoded Location
			require.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, tt.location.Coordinates, decoded.Coordinates, "decoding fills FullPath back in")
			assert.Equal(t, tt.location.AccessPath, decoded.AccessPath)

			data, err = json.Marshal(tt.location.Coordinates)
			require.NoError(t, err)
			var coordinates Coordinates
			require.NoError(t, json.Unmarshal(data, &coordinates))
			assert.Equal(t, tt.location.Coordinates, coordinates)
		})
	}
}

func TestCoordinates_ID_unchangedByTopLevelFullRealPath(t *testing.T) {
	assert.Equal(t, Coordinates{RealPath: "/a"}.ID(), NewCoordinates("/a", "").ID())
	assert.NotEqual(t, NewCoordinates("/a", "").ID(), Coordinates{RealPath: "/a", FullPath: "/a!/b"}.ID())
}

func TestCoordinates_LocalPath(t *testing.T) {
	assert.Equal(t, "/a.jar", NewCoordinates("/a.jar", "").LocalPath())
	assert.Equal(t, "/a.jar", Coordinates{RealPath: "/a.jar"}.LocalPath())
	assert.Equal(t, "/META-INF/MANIFEST.MF", Coordinates{RealPath: "/a.war", FullPath: "/a.war!/lib/b.jar!/META-INF/MANIFEST.MF"}.LocalPath())
	assert.Equal(t, "/data/Hello!/world.txt", NewCoordinates("/data/Hello!/world.txt", "").LocalPath(), "a separator in a real path is not an archive boundary")
	assert.Equal(t, "/data/Hello!/world.txt", Coordinates{RealPath: "/data/Hello!/world.txt", FullPath: "/data/Hello!/world.txt"}.LocalPath())
	assert.Equal(t, "/x.txt", Coordinates{RealPath: "/data/Hello!/a.zip", FullPath: "/data/Hello!/a.zip!/x.txt"}.LocalPath())
	assert.Equal(t, "/x.txt", Coordinates{RealPath: "/data/Hello!/a.zip", FullPath: "/data/Hello!/a.zip!/b.jar!/x.txt"}.LocalPath())
}

func TestLocation_Path(t *testing.T) {
	nested := Coordinates{RealPath: "/a.war", FullPath: "/a.war!/lib/b.jar!/META-INF/MANIFEST.MF"}
	assert.Equal(t, "/a.jar", NewLocation("/a.jar").Path())
	assert.Equal(t, "/link", NewVirtualLocation("/a.jar", "/link").Path())
	assert.Equal(t, nested.FullPath, NewLocationFromCoordinates(nested).Path())
	assert.Equal(t, nested.FullPath, Location{LocationData: LocationData{Coordinates: nested}}.Path(), "a nested location without an access path is still full")
	assert.Equal(t, nested.FullPath, NewVirtualLocationFromCoordinates(nested, nested.FullPath).Path())
}
