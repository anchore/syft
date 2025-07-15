package file

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/internal/evidence"
)

func TestLocationAndCoordinatesSorters(t *testing.T) {
	tests := []struct {
		name       string
		layers     []string
		locs       []Location
		coords     []Coordinates
		wantLocs   []string
		wantCoords []string
	}{
		{
			name:       "empty location slice",
			layers:     []string{"fsid-1"},
			locs:       []Location{},
			coords:     []Coordinates{},
			wantLocs:   []string{},
			wantCoords: []string{},
		},
		{
			name:   "nil layer list",
			layers: nil,
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "fsid-2",
				},
			},
			wantLocs: []string{
				"/a (/a) @ fsid-1 map[]",
				"/b (/b) @ fsid-2 map[]",
			},
			wantCoords: []string{
				"/a @ fsid-1",
				"/b @ fsid-2",
			},
		},
		{
			name:   "sort by evidence type only",
			layers: []string{"fsid-1"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: "",
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.SupportingAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/c",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/c",
					FileSystemID: "fsid-1",
				},
			},
			wantLocs: []string{
				"/c (/c) @ fsid-1 map[evidence:primary]",
				"/b (/b) @ fsid-1 map[evidence:supporting]",
				"/a (/a) @ fsid-1 map[evidence:]",
			},
			wantCoords: []string{
				"/a @ fsid-1",
				"/b @ fsid-1",
				"/c @ fsid-1",
			},
		},
		{
			name:   "same evidence type, sort by layer",
			layers: []string{"fsid-1", "fsid-2", "fsid-3"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-3",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/c",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "fsid-3",
				},
				{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/c",
					FileSystemID: "fsid-2",
				},
			},
			wantLocs: []string{
				"/b (/b) @ fsid-1 map[evidence:primary]",
				"/c (/c) @ fsid-2 map[evidence:primary]",
				"/a (/a) @ fsid-3 map[evidence:primary]",
			},
			wantCoords: []string{
				"/b @ fsid-1",
				"/c @ fsid-2",
				"/a @ fsid-3",
			},
		},
		{
			name:   "same evidence and layer, sort by access path",
			layers: []string{"fsid-1"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/x",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/c",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/y",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/z",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/x",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/y",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/z",
					FileSystemID: "fsid-1",
				},
			},
			wantLocs: []string{
				"/y (/a) @ fsid-1 map[evidence:primary]",
				"/z (/b) @ fsid-1 map[evidence:primary]",
				"/x (/c) @ fsid-1 map[evidence:primary]",
			},
			wantCoords: []string{
				"/x @ fsid-1",
				"/y @ fsid-1",
				"/z @ fsid-1",
			},
		},
		{
			name:   "same evidence, layer, and access path - sort by real path",
			layers: []string{"fsid-1"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/same",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/same",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/same",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/c",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				},
			},
			wantLocs: []string{
				"/a (/same) @ fsid-1 map[evidence:primary]",
				"/b (/same) @ fsid-1 map[evidence:primary]",
				"/c (/same) @ fsid-1 map[evidence:primary]",
			},
			wantCoords: []string{
				"/a @ fsid-1",
				"/b @ fsid-1",
				"/c @ fsid-1",
			},
		},
		{
			name:   "unknown layers",
			layers: []string{"fsid-1", "fsid-2"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "unknown-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "unknown-2",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "unknown-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "unknown-2",
				},
			},
			wantLocs: []string{
				"/a (/a) @ unknown-1 map[]",
				"/b (/b) @ unknown-2 map[]",
			},
			wantCoords: []string{
				"/a @ unknown-1",
				"/b @ unknown-2",
			},
		},
		{
			name:   "mixed known and unknown layers",
			layers: []string{"fsid-1", "fsid-2"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "unknown",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "unknown",
				},
			},
			wantLocs: []string{
				"/a (/a) @ fsid-1 map[]",
				"/b (/b) @ unknown map[]",
			},
			wantCoords: []string{
				"/a @ fsid-1",
				"/b @ unknown",
			},
		},
		{
			name:   "evidence comparison when one has none",
			layers: []string{"fsid-1"},
			locs: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							// No evidence.AnnotationKey
						},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			coords: []Coordinates{
				{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				},
				{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				},
			},
			wantLocs: []string{
				"/b (/b) @ fsid-1 map[evidence:primary]",
				"/a (/a) @ fsid-1 map[]",
			},
			wantCoords: []string{
				"/a @ fsid-1",
				"/b @ fsid-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("Location", func(t *testing.T) {
				locs := make([]Location, len(tt.locs))
				copy(locs, tt.locs)

				slices.SortFunc(locs, LocationSorter(tt.layers))

				got := make([]string, len(locs))
				for i, loc := range locs {
					got[i] = fmt.Sprintf("%s (%s) @ %s %s",
						loc.RealPath,
						loc.AccessPath,
						loc.FileSystemID,
						loc.LocationMetadata.Annotations)
				}

				if d := cmp.Diff(tt.wantLocs, got); d != "" {
					t.Errorf("LocationSorter() mismatch (-want +got):\n%s", d)
				}
			})

			t.Run("Coordinates", func(t *testing.T) {
				coords := make([]Coordinates, len(tt.coords))
				copy(coords, tt.coords)

				slices.SortFunc(coords, CoordinatesSorter(tt.layers))

				got := make([]string, len(coords))
				for i, coord := range coords {
					got[i] = fmt.Sprintf("%s @ %s",
						coord.RealPath,
						coord.FileSystemID)
				}

				if d := cmp.Diff(tt.wantCoords, got); d != "" {
					t.Errorf("CoordinatesSorter() mismatch (-want +got):\n%s", d)
				}
			})
		})
	}
}
