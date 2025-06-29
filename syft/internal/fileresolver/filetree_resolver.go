package fileresolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/windows"
)

type filetreeResolver struct {
	chroot        ChrootContext
	tree          filetree.Reader
	index         filetree.IndexReader
	searchContext filetree.Searcher

	realPath   string
	accessPath string
	tempDir    string
	archives   []*filetreeResolver
}

func (r *filetreeResolver) requestPath(userPath string) (string, error) {
	requestPath, err := r.chroot.ToNativePath(userPath)
	if err != nil {
		return "", err
	}

	if r.accessPath != "" && r.tempDir != "" {
		return strings.Replace(requestPath, r.accessPath, r.tempDir, 1), nil
	}

	return requestPath, nil
}

// responsePath takes a path from the underlying fs domain and converts it to a path that is relative to the root of the file resolver.
func (r filetreeResolver) responsePath(path string) string {
	if r.tempDir != "" && strings.HasPrefix(path, r.tempDir) {
		path = r.realPath
	}
	return r.chroot.ToChrootPath(path)
}

func (r filetreeResolver) responseAccessPath(path string) string {
	responsePath := strings.Replace(path, r.tempDir, r.accessPath, 1)
	return r.chroot.ToChrootPath(responsePath)
}

// HasPath indicates if the given path exists in the underlying source.
func (r *filetreeResolver) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}

	if r.tree.HasPath(stereoscopeFile.Path(requestPath)) {
		return true
	}

	for _, archive := range r.archives {
		if archive.HasPath(userPath) {
			return true
		}
	}

	return false
}

// FilesByPath returns all file.References that match the given paths from the file index.
func (r filetreeResolver) FilesByPath(userPaths ...string) ([]file.Location, error) {
	var references = make([]file.Location, 0)

	for _, userPath := range userPaths {
		userStrPath, err := r.requestPath(userPath)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// we should be resolving symlinks and preserving this information as a AccessPath to the real file
		ref, err := r.searchContext.SearchByPath(userStrPath, filetree.FollowBasenameLinks)
		if err != nil {
			log.Tracef("unable to evaluate symlink for path=%q : %+v", userPath, err)
			continue
		}

		if !ref.HasReference() {
			continue
		}

		entry, err := r.index.Get(*ref.Reference)
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
				file.NewVirtualLocationFromDirectory(
					r.responsePath(string(ref.RealPath)), // the actual path relative to the resolver root
					r.responseAccessPath(userStrPath),    // the path used to access this file, relative to the resolver root
					*ref.Reference,
				),
			)
		}
	}

	for _, archive := range r.archives {
		locations, err := archive.FilesByPath(userPaths...)
		if err != nil {
			return nil, err
		}
		references = append(references, locations...)
	}

	return references, nil
}

func (r filetreeResolver) requestGlob(pattern string) (string, error) {
	nativeGlob, err := r.chroot.ToNativeGlob(pattern)
	if err != nil {
		return "", err
	}

	return strings.Replace(nativeGlob, r.accessPath, r.tempDir, 1), nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r filetreeResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		requestGlob, err := r.requestGlob(pattern)
		if err != nil {
			return nil, err
		}
		refVias, err := r.searchContext.SearchByGlob(requestGlob, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, refVia := range refVias {
			if !refVia.HasReference() || uniqueFileIDs.Contains(*refVia.Reference) {
				continue
			}
			entry, err := r.index.Get(*refVia.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for reference %s: %w", refVia.RealPath, err)
			}

			// don't consider directories
			if entry.IsDir() {
				continue
			}

			loc := file.NewVirtualLocationFromDirectory(
				r.responsePath(string(refVia.RealPath)),          // the actual path relative to the resolver root
				r.responseAccessPath(string(refVia.RequestPath)), // the path used to access this file, relative to the resolver root
				*refVia.Reference,
			)
			uniqueFileIDs.Add(*refVia.Reference)
			uniqueLocations = append(uniqueLocations, loc)
		}
	}

	for _, archive := range r.archives {
		archiveUniqueLocations, err := archive.FilesByGlob(patterns...)
		if err != nil {
			return nil, err
		}

		for _, archiveUniqueLocation := range archiveUniqueLocations {
			if uniqueFileIDs.Contains(archiveUniqueLocation.Reference()) {
				continue
			}
			uniqueLocations = append(uniqueLocations, archiveUniqueLocation)
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *filetreeResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
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
func (r filetreeResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if location.RealPath == "" {
		return nil, errors.New("empty path given")
	}

	entry, err := r.index.Get(location.Reference())
	if err != nil {
		for _, archive := range r.archives {
			entry, err = archive.index.Get(location.Reference())
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}

	// don't consider directories
	if entry.Type == stereoscopeFile.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.Reference().RealPath)
	}

	// RealPath is posix so for windows file resolver we need to translate
	// to its true on disk path.
	filePath := string(location.Reference().RealPath)
	if windows.HostRunningOnWindows() {
		filePath = windows.FromPosix(filePath)
	}

	return stereoscopeFile.NewLazyReadCloser(filePath), nil
}

func (r *filetreeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.tree.AllFiles(stereoscopeFile.AllTypes()...) {
			select {
			case <-ctx.Done():
				return
			case results <- file.NewVirtualLocationFromDirectory(r.responsePath(string(ref.RealPath)), r.responseAccessPath(string(ref.RealPath)), ref):
				continue
			}
		}

		for _, archive := range r.archives {
			for location := range archive.AllLocations(ctx) {
				select {
				case <-ctx.Done():
					return
				case results <- location:
					continue
				}
			}
		}
	}()
	return results
}

func (r *filetreeResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := r.index.Get(location.Reference())
	if err == nil {
		return entry.Metadata, nil
	}

	for _, archive := range r.archives {
		entry, err = archive.index.Get(location.Reference())
		if err == nil {
			return entry.Metadata, nil
		}
	}

	return file.Metadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
}

func (r *filetreeResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	refVias, err := r.searchContext.SearchByMIMEType(types...)
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
		location := file.NewVirtualLocationFromDirectory(
			r.responsePath(string(refVia.RealPath)),
			r.responseAccessPath(string(refVia.RequestPath)),
			*refVia.Reference,
		)
		uniqueFileIDs.Add(*refVia.Reference)
		uniqueLocations = append(uniqueLocations, location)
	}

	for _, archive := range r.archives {
		archiveUniqueLocations, err := archive.FilesByMIMEType(types...)
		if err != nil {
			return nil, err
		}

		for _, archiveUniqueLocation := range archiveUniqueLocations {
			if uniqueFileIDs.Contains(archiveUniqueLocation.Reference()) {
				continue
			}
			uniqueLocations = append(uniqueLocations, archiveUniqueLocation)
		}
	}

	return uniqueLocations, nil
}
