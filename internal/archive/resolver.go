package archive

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/anchore/syft/syft/file"
)

const (
	// ArchivePathSeparator is used to encode nested archive paths in AccessPath,
	// matching the convention established by the Java cataloger.
	ArchivePathSeparator = ":"
)

// childResolver holds a resolver for an extracted archive along with metadata about the archive.
type childResolver struct {
	resolver       file.Resolver
	archiveLocation file.Location // where the archive file lives in the parent resolver
	fsID           string        // unique filesystem ID for this archive
	depth          int           // nesting depth (0 = base filesystem)
}

// CompositeResolver implements file.Resolver by compositing a parent resolver with
// child resolvers created from extracted archive contents. Files from child resolvers
// appear transparently alongside files from the parent.
type CompositeResolver struct {
	parent   file.Resolver
	children []*childResolver
	mu       sync.RWMutex
}

var _ file.Resolver = (*CompositeResolver)(nil)

// NewCompositeResolver creates a new CompositeResolver wrapping the given parent resolver.
func NewCompositeResolver(parent file.Resolver) *CompositeResolver {
	return &CompositeResolver{
		parent: parent,
	}
}

// AddChild registers a child resolver for an extracted archive.
func (r *CompositeResolver) AddChild(resolver file.Resolver, archiveLocation file.Location, depth int) string {
	fsID := generateArchiveFSID(archiveLocation)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.children = append(r.children, &childResolver{
		resolver:       resolver,
		archiveLocation: archiveLocation,
		fsID:           fsID,
		depth:          depth,
	})
	return fsID
}

// ChildCount returns the number of child resolvers registered.
func (r *CompositeResolver) ChildCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.children)
}

// HasPath checks if the path exists in the parent or any child resolver.
func (r *CompositeResolver) HasPath(path string) bool {
	if r.parent.HasPath(path) {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		if child.resolver.HasPath(path) {
			return true
		}
	}
	return false
}

// FilesByPath returns locations from the parent and all child resolvers.
func (r *CompositeResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location

	parentLocs, err := r.parent.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}
	results = append(results, parentLocs...)

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		childLocs, err := child.resolver.FilesByPath(paths...)
		if err != nil {
			continue
		}
		for _, loc := range childLocs {
			results = append(results, r.transformLocation(loc, child))
		}
	}

	return results, nil
}

// FilesByGlob returns locations from the parent and all child resolvers.
func (r *CompositeResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var results []file.Location

	parentLocs, err := r.parent.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}
	results = append(results, parentLocs...)

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		childLocs, err := child.resolver.FilesByGlob(patterns...)
		if err != nil {
			continue
		}
		for _, loc := range childLocs {
			results = append(results, r.transformLocation(loc, child))
		}
	}

	return results, nil
}

// FilesByMIMEType returns locations from the parent and all child resolvers.
func (r *CompositeResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	var results []file.Location

	parentLocs, err := r.parent.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	results = append(results, parentLocs...)

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		childLocs, err := child.resolver.FilesByMIMEType(types...)
		if err != nil {
			continue
		}
		for _, loc := range childLocs {
			results = append(results, r.transformLocation(loc, child))
		}
	}

	return results, nil
}

// RelativeFileByPath looks up a file relative to a given location.
func (r *CompositeResolver) RelativeFileByPath(location file.Location, path string) *file.Location {
	// try parent first
	if loc := r.parent.RelativeFileByPath(location, path); loc != nil {
		return loc
	}

	// try children - match on the archive's FSID
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		if location.FileSystemID == child.fsID {
			if loc := child.resolver.RelativeFileByPath(location, path); loc != nil {
				transformed := r.transformLocation(*loc, child)
				return &transformed
			}
		}
	}
	return nil
}

// FileContentsByLocation routes to the appropriate resolver based on FileSystemID.
func (r *CompositeResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	// check if this location belongs to a child resolver
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		if location.FileSystemID == child.fsID {
			// look up the file by path in the child resolver to get a location with
			// a valid internal reference (needed by directory resolvers that use
			// stereoscope file references for content lookup)
			childLocs, err := child.resolver.FilesByPath(location.RealPath)
			if err != nil || len(childLocs) == 0 {
				// fallback: try with a constructed location
				childLoc := file.NewLocation(location.RealPath)
				return child.resolver.FileContentsByLocation(childLoc)
			}
			return child.resolver.FileContentsByLocation(childLocs[0])
		}
	}

	// fall through to parent
	return r.parent.FileContentsByLocation(location)
}

// AllLocations returns locations from the parent and all child resolvers.
func (r *CompositeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)

		// parent locations
		for loc := range r.parent.AllLocations(ctx) {
			select {
			case <-ctx.Done():
				return
			case results <- loc:
			}
		}

		// child locations
		r.mu.RLock()
		children := make([]*childResolver, len(r.children))
		copy(children, r.children)
		r.mu.RUnlock()

		for _, child := range children {
			for loc := range child.resolver.AllLocations(ctx) {
				transformed := r.transformLocation(loc, child)
				select {
				case <-ctx.Done():
					return
				case results <- transformed:
				}
			}
		}
	}()
	return results
}

// FileMetadataByLocation routes to the appropriate resolver based on FileSystemID.
func (r *CompositeResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, child := range r.children {
		if location.FileSystemID == child.fsID {
			childLocs, err := child.resolver.FilesByPath(location.RealPath)
			if err != nil || len(childLocs) == 0 {
				childLoc := file.NewLocation(location.RealPath)
				return child.resolver.FileMetadataByLocation(childLoc)
			}
			return child.resolver.FileMetadataByLocation(childLocs[0])
		}
	}
	return r.parent.FileMetadataByLocation(location)
}

// transformLocation transforms a location from a child resolver to include the archive context.
func (r *CompositeResolver) transformLocation(loc file.Location, child *childResolver) file.Location {
	archivePath := child.archiveLocation.Path()
	return file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{
				RealPath:     loc.RealPath,
				FileSystemID: child.fsID,
			},
			AccessPath: archivePath + ArchivePathSeparator + loc.Path(),
		},
		LocationMetadata: loc.LocationMetadata,
	}
}

// generateArchiveFSID creates a deterministic filesystem ID for an archive based on its location.
func generateArchiveFSID(archiveLocation file.Location) string {
	h := sha256.New()
	h.Write([]byte(archiveLocation.RealPath))
	h.Write([]byte(archiveLocation.FileSystemID))
	return fmt.Sprintf("archive:%x", h.Sum(nil)[:12])
}
