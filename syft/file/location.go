package file

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

const (
	// VisibleAnnotationKey is the key used to indicate if the location is visible or not at runtime
	VisibleAnnotationKey = "visible"

	// HiddenAnnotation is the value used to indicate that the location is not visible at runtime because it was deleted
	HiddenAnnotation = "false"

	// VisibleAnnotation is the value used to indicate that the location is visible at runtime
	VisibleAnnotation = "true"
)

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the AccessPath).
type Location struct {
	LocationData     `cyclonedx:""`
	LocationMetadata `cyclonedx:""`
}

// LocationData contains the core identifying information for a file location.
type LocationData struct {
	Coordinates `cyclonedx:""` // Empty string here means there is no intermediate property name, e.g. syft:locations:0:path without "coordinates"
	// note: it is IMPORTANT to ignore anything but the coordinates for a Location when considering the ID (hash value)
	// since the coordinates are the minimally correct ID for a location (symlinks should not come into play)

	// AccessPath is the path used to retrieve file contents (which may or may not have hardlinks / symlinks in the path)
	AccessPath string `hash:"ignore" json:"accessPath"`

	// ref is the stereoscope file reference relative to the stereoscope.FileCatalog that has more information about this location.
	ref file.Reference `hash:"ignore"`
}

func (l LocationData) Reference() file.Reference {
	return l.ref
}

// LocationMetadata provides additional contextual information about a file location.
type LocationMetadata struct {
	Annotations map[string]string `json:"annotations,omitempty"` // Arbitrary key-value pairs that can be used to annotate a location
}

func (m *LocationMetadata) merge(other LocationMetadata) error {
	var errs error
	for k, v := range other.Annotations {
		if otherV, ok := m.Annotations[k]; ok {
			if v != otherV {
				err := fmt.Errorf("unable to merge location metadata: conflicting values for key=%q: %q != %q", k, v, otherV)
				errs = multierror.Append(errs, err)
				continue
			}
		}
		m.Annotations[k] = v
	}
	return errs
}

func (l Location) WithAnnotation(key, value string) Location {
	if key == "" || value == "" {
		return l
	}
	if l.Annotations == nil {
		l.Annotations = map[string]string{}
	}
	l.Annotations[key] = value
	return l
}

func (l Location) WithoutAnnotations() Location {
	l.Annotations = map[string]string{}

	return l
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
func NewLocation(realPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
			AccessPath: realPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewVirtualLocation creates a new location for a path accessed by a virtual path (a path with a symlink or hardlink somewhere in the path)
func NewVirtualLocation(realPath, accessPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
			AccessPath: accessPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewLocationFromCoordinates creates a new location for the given Coordinates.
func NewLocationFromCoordinates(coordinates Coordinates) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
			AccessPath:  coordinates.RealPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewVirtualLocationFromCoordinates creates a new location for the given Coordinates via a virtual path.
func NewVirtualLocationFromCoordinates(coordinates Coordinates, accessPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
			AccessPath:  accessPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the Reference) relative to the given image.
func NewLocationFromImage(accessPath string, ref file.Reference, img *image.Image) Location {
	layer := img.FileCatalog.Layer(ref)
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     string(ref.RealPath),
				FileSystemID: layer.Metadata.Digest,
			},
			AccessPath: accessPath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory.
func NewLocationFromDirectory(responsePath string, fd string, ref file.Reference) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     responsePath,
				FileSystemID: fd,
			},
			AccessPath: responsePath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewVirtualLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory with a separate virtual access path.
func NewVirtualLocationFromDirectory(responsePath, responseAccessPath string, ref file.Reference) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: responsePath,
			},
			AccessPath: responseAccessPath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

func (l Location) Path() string {
	if l.AccessPath != "" {
		return l.AccessPath
	}
	return l.RealPath
}

func (l Location) String() string {
	str := ""
	if l.ref.ID() != 0 {
		str += fmt.Sprintf("id=%d ", l.ref.ID())
	}

	str += fmt.Sprintf("RealPath=%q", l.RealPath)

	if l.AccessPath != "" && l.AccessPath != l.RealPath {
		str += fmt.Sprintf(" AccessPath=%q", l.AccessPath)
	}

	if l.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", l.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (l Location) Equals(other Location) bool {
	return l.RealPath == other.RealPath &&
		l.AccessPath == other.AccessPath &&
		l.FileSystemID == other.FileSystemID
}
