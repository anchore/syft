package fileresolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/windows"
)

// TODO: consider making a constructor for this
type FiletreeResolver struct {
	Chroot        ChrootContext
	Tree          filetree.Reader
	Index         filetree.IndexReader
	SearchContext filetree.Searcher
	Opener        func(stereoscopeFile.Reference) (io.ReadCloser, error)

	// FileSystemID, when non-empty, is stamped onto the Coordinates of every Location this
	// resolver returns. For container images this is a layer digest; for an extracted archive
	// treated as its own standalone filesystem it is the FileSystemID of the archive file's own
	// filesystem (inherited unchanged down the nesting chain); for a plain root directory scan it
	// is empty.
	FileSystemID string

	// ArchivePath, when non-empty, is stamped onto the Coordinates of every Location this resolver
	// returns. For an archive extracted and indexed as its own standalone filesystem it is the
	// colon-delimited chain of archive paths from the scan root to that archive (e.g.
	// "app.war:WEB-INF/lib/dep.jar"); for a plain root directory scan it is empty. This keeps
	// identically-named files in different archives from colliding in the coordinate-keyed SBOM
	// tables.
	ArchivePath string
}

// newVirtualLocation builds a directory location with a distinct access path, stamped with this
// resolver's FileSystemID and ArchivePath.
func (r FiletreeResolver) newVirtualLocation(responsePath, responseAccessPath string, ref stereoscopeFile.Reference) file.Location {
	loc := file.NewVirtualLocationFromDirectory(responsePath, responseAccessPath, ref)
	loc.FileSystemID = r.FileSystemID
	loc.ArchivePath = r.ArchivePath
	return loc
}

func nativeOSFileOpener(ref stereoscopeFile.Reference) (io.ReadCloser, error) {
	// RealPath is posix so for windows file resolver we need to translate
	// to its true on disk path.
	filePath := string(ref.RealPath)
	if windows.HostRunningOnWindows() {
		filePath = windows.FromPosix(filePath)
	}

	return stereoscopeFile.NewLazyReadCloser(filePath), nil
}

func (r *FiletreeResolver) requestPath(userPath string) (string, error) {
	return r.Chroot.ToNativePath(userPath)
}

// responsePath takes a path from the underlying fs domain and converts it to a path that is relative to the root of the file resolver.
func (r FiletreeResolver) responsePath(path string) string {
	return r.Chroot.ToChrootPath(path)
}

// HasPath indicates if the given path exists in the underlying source.
func (r *FiletreeResolver) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}
	return r.Tree.HasPath(stereoscopeFile.Path(requestPath))
}

// FilesByPath returns all file.References that match the given paths from the file index.
func (r FiletreeResolver) FilesByPath(userPaths ...string) ([]file.Location, error) {
	var references = make([]file.Location, 0)

	for _, userPath := range userPaths {
		userStrPath, err := r.requestPath(userPath)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// we should be resolving symlinks and preserving this information as a AccessPath to the real file
		ref, err := r.SearchContext.SearchByPath(userStrPath, filetree.FollowBasenameLinks)
		if err != nil {
			log.Tracef("unable to evaluate symlink for path=%q : %+v", userPath, err)
			continue
		}

		if !ref.HasReference() {
			continue
		}

		entry, err := r.Index.Get(*ref.Reference)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// don't consider directories
		if entry.IsDir() {
			continue
		}

		if windows.HostRunningOnWindows() {
			userStrPath = windows.ToPosix(userStrPath)
		}

		if ref.HasReference() {
			references = append(references,
				r.newVirtualLocation(
					r.responsePath(string(ref.RealPath)), // the actual path relative to the resolver root
					r.responsePath(userStrPath),          // the path used to access this file, relative to the resolver root
					*ref.Reference,
				),
			)
		}
	}

	return references, nil
}

func (r FiletreeResolver) requestGlob(pattern string) (string, error) {
	return r.Chroot.ToNativeGlob(pattern)
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r FiletreeResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		requestGlob, err := r.requestGlob(pattern)
		if err != nil {
			return nil, err
		}
		refVias, err := r.SearchContext.SearchByGlob(requestGlob, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, refVia := range refVias {
			if !refVia.HasReference() || uniqueFileIDs.Contains(*refVia.Reference) {
				continue
			}
			entry, err := r.Index.Get(*refVia.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for reference %s: %w", refVia.RealPath, err)
			}

			// don't consider directories
			if entry.IsDir() {
				continue
			}

			loc := r.newVirtualLocation(
				r.responsePath(string(refVia.RealPath)),    // the actual path relative to the resolver root
				r.responsePath(string(refVia.RequestPath)), // the path used to access this file, relative to the resolver root
				*refVia.Reference,
			)
			uniqueFileIDs.Add(*refVia.Reference)
			uniqueLocations = append(uniqueLocations, loc)
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *FiletreeResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// FileContentsByLocation fetches file contents for a single file reference relative to a directory.
// If the path does not exist an error is returned.
func (r FiletreeResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if location.RealPath == "" {
		return nil, errors.New("empty path given")
	}

	entry, err := r.Index.Get(location.Reference())
	if err != nil {
		return nil, err
	}

	// don't consider directories
	if entry.Type == stereoscopeFile.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.Reference().RealPath)
	}

	return r.Opener(location.Reference())
}

func (r *FiletreeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.Tree.AllFiles(stereoscopeFile.AllTypes()...) {
			responsePath := r.responsePath(string(ref.RealPath))
			if r.FileSystemID != "" && filepath.IsAbs(responsePath) {
				// ToChrootPath relativizes by trimming the prefix root + "/", which cannot match
				// the root path itself, so the resolver's own root arrives here still absolute.
				// For a directory scan that is the path the user asked for and is left alone. For a
				// filesystem this capability invented - an archive extracted into a directory
				// created fresh per run - it is a path that must not reach a coordinate: it would
				// make two scans of identical input produce different output, and it names a
				// directory that no longer exists by the time the scan finishes. Gated on
				// FileSystemID so directory and image scans behave exactly as before.
				continue
			}
			loc := file.NewLocationFromDirectory(responsePath, r.FileSystemID, ref)
			loc.ArchivePath = r.ArchivePath
			select {
			case <-ctx.Done():
				return
			case results <- loc:
				continue
			}
		}
	}()
	return results
}

func (r *FiletreeResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := r.Index.Get(location.Reference())
	if err != nil {
		return file.Metadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	return entry.Metadata, nil
}

func (r *FiletreeResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	refVias, err := r.SearchContext.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	for _, refVia := range refVias {
		if !refVia.HasReference() {
			continue
		}
		if uniqueFileIDs.Contains(*refVia.Reference) {
			continue
		}
		location := r.newVirtualLocation(
			r.responsePath(string(refVia.RealPath)),
			r.responsePath(string(refVia.RequestPath)),
			*refVia.Reference,
		)
		uniqueFileIDs.Add(*refVia.Reference)
		uniqueLocations = append(uniqueLocations, location)
	}

	return uniqueLocations, nil
}
