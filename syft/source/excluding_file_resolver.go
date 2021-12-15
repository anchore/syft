package source

import (
	"io"
	"os"
)

type excludeFn func(string, os.FileInfo) bool

type excludingResolver struct {
	delegate  FileResolver
	excludeFn excludeFn
}

func NewExcludingResolver(delegate FileResolver, excludeFn excludeFn) FileResolver {
	return &excludingResolver{
		delegate,
		excludeFn,
	}
}

func (r *excludingResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	return r.delegate.FileContentsByLocation(location)
}

func (r *excludingResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	return r.delegate.FileMetadataByLocation(location)
}

func (r *excludingResolver) HasPath(path string) bool {
	return r.delegate.HasPath(path)
}

func (r *excludingResolver) FilesByPath(paths ...string) ([]Location, error) {
	locations, err := r.delegate.FilesByPath(paths...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	locations, err := r.delegate.FilesByGlob(patterns...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	locations, err := r.delegate.FilesByMIMEType(types...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) RelativeFileByPath(location Location, path string) *Location {
	return r.delegate.RelativeFileByPath(location, path)
}

func (r *excludingResolver) AllLocations() <-chan Location {
	return r.delegate.AllLocations()
}

func filterLocations(locations []Location, err error, exclusionFn excludeFn) ([]Location, error) {
	if err != nil {
		return nil, err
	}
	if exclusionFn != nil {
		for i := 0; i < len(locations); i++ {
			location := locations[i]
			if exclusionFn(location.RealPath, nil) || exclusionFn(location.VirtualPath, nil) {
				locations = append(locations[:i], locations[i+1:]...)
				i--
			}
		}
	}
	return locations, nil
}
