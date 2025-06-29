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

// TODO: consider making a constructor for this
type FiletreeResolver struct {
	Chroot        ChrootContext
	Tree          filetree.Reader
	Index         filetree.IndexReader
	SearchContext filetree.Searcher
	Opener        func(stereoscopeFile.Reference) (io.ReadCloser, error)

	realPath        string
	accessPath      string
	archiveRealPath string
	archives        []*FiletreeResolver
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
	requestPath, err := r.Chroot.ToNativePath(userPath)
	if err != nil {
		return "", err
	}

	if r.accessPath != "" && r.archiveRealPath != "" {
		return strings.Replace(requestPath, r.accessPath, r.archiveRealPath, 1), nil
	}

	return requestPath, nil
}

// responsePath takes a path from the underlying fs domain and converts it to a path that is relative to the root of the file resolver.
func (r FiletreeResolver) responsePath(path string) string {
	if r.archiveRealPath != "" && strings.HasPrefix(path, r.archiveRealPath) {
		path = r.realPath
	}

	return r.Chroot.ToChrootPath(path)
}

func (r FiletreeResolver) responseAccessPath(path string) string {
	if r.accessPath != "" && r.archiveRealPath != "" {
		path = strings.Replace(path, r.archiveRealPath, r.accessPath, 1)
	}

	return r.Chroot.ToChrootPath(path)
}

// HasPath indicates if the given path exists in the underlying source.
func (r *FiletreeResolver) HasPath(userPath string) bool {
	requestPath, err := r.requestPath(userPath)
	if err != nil {
		return false
	}

	if r.Tree.HasPath(stereoscopeFile.Path(requestPath)) {
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

func (r FiletreeResolver) requestGlob(pattern string) (string, error) {
	nativeGlob, err := r.Chroot.ToNativeGlob(pattern)
	if err != nil {
		return "", err
	}

	if r.accessPath != "" && r.archiveRealPath != "" {
		return strings.Replace(nativeGlob, r.accessPath, r.archiveRealPath, 1), nil
	}

	return nativeGlob, nil
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
		for _, archive := range r.archives {
			entry, err = archive.Index.Get(location.Reference())
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

	return r.Opener(location.Reference())
}

func (r *FiletreeResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.Tree.AllFiles(stereoscopeFile.AllTypes()...) {
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

func (r *FiletreeResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := r.Index.Get(location.Reference())
	if err == nil {
		return entry.Metadata, nil
	}

	for _, archive := range r.archives {
		entry, err = archive.Index.Get(location.Reference())
		if err == nil {
			return entry.Metadata, nil
		}
	}

	return file.Metadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
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
