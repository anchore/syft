package file

import (
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/internal/evidence"
)

func TestLocationsByContainerOrder(t *testing.T) {
	tests := []struct {
		name               string
		locations          []Location
		layerOrderByDigest map[string]int
		want               []string
	}{
		{
			name:               "empty location slice",
			locations:          []Location{},
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want:               []string{},
		},
		{
			name: "nil layer order map",
			locations: []Location{
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
			layerOrderByDigest: nil,
			want: []string{
				"/a (/a) @ fsid-1 map[]",
				"/b (/b) @ fsid-2 map[]",
			},
		},
		{
			name: "sort by evidence type only",
			locations: []Location{
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
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want: []string{
				"/c (/c) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/b (/b) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.SupportingAnnotation + "]",
				"/a (/a) @ fsid-1 map[" + evidence.AnnotationKey + ":]",
			},
		},
		{
			name: "same evidence type, sort by layer",
			locations: []Location{
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
			layerOrderByDigest: map[string]int{
				"fsid-1": 1,
				"fsid-2": 2,
				"fsid-3": 3,
			},
			want: []string{
				"/b (/b) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/c (/c) @ fsid-2 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/a (/a) @ fsid-3 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
			},
		},
		{
			name: "same evidence and layer, sort by access path",
			locations: []Location{
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
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want: []string{
				"/y (/a) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/z (/b) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/x (/c) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
			},
		},
		{
			name: "same evidence, layer, and access path - sort by real path",
			locations: []Location{
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
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want: []string{
				"/a (/same) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/b (/same) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/c (/same) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
			},
		},
		{
			name: "mixed evidence and layers",
			locations: []Location{
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
							FileSystemID: "fsid-2",
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
							FileSystemID: "fsid-3",
						},
						AccessPath: "/c",
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
							RealPath:     "/d",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/d",
					},
					LocationMetadata: LocationMetadata{
						Annotations: map[string]string{
							evidence.AnnotationKey: evidence.PrimaryAnnotation,
						},
					},
				},
			},
			layerOrderByDigest: map[string]int{
				"fsid-1": 1,
				"fsid-2": 2,
				"fsid-3": 3,
			},
			want: []string{
				"/d (/d) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/b (/b) @ fsid-2 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/c (/c) @ fsid-3 map[" + evidence.AnnotationKey + ":" + evidence.SupportingAnnotation + "]",
				"/a (/a) @ fsid-1 map[" + evidence.AnnotationKey + ":]",
			},
		},
		{
			name: "evidence comparison when one has none",
			locations: []Location{
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
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want: []string{
				"/b (/b) @ fsid-1 map[" + evidence.AnnotationKey + ":" + evidence.PrimaryAnnotation + "]",
				"/a (/a) @ fsid-1 map[]",
			},
		},
		{
			name: "evidence value comparison",
			locations: []Location{
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
							evidence.AnnotationKey: "xyz", // some arbitrary value
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
							evidence.AnnotationKey: "abc", // some arbitrary value less than xyz
						},
					},
				},
			},
			layerOrderByDigest: map[string]int{"fsid-1": 1},
			want: []string{
				"/a (/a) @ fsid-1 map[" + evidence.AnnotationKey + ":xyz]",
				"/b (/b) @ fsid-1 map[" + evidence.AnnotationKey + ":abc]",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locations := make([]Location, len(tt.locations))
			copy(locations, tt.locations)

			sort.Sort(LocationsByContainerOrder(locations, tt.layerOrderByDigest))

			got := make([]string, len(locations))
			for i, loc := range locations {
				got[i] = fmt.Sprintf("%s (%s) @ %s %s",
					loc.RealPath,
					loc.AccessPath,
					loc.FileSystemID,
					loc.LocationMetadata.Annotations)
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("LocationsByContainerOrder() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
