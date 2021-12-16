package source

import (
	"fmt"
	"io"
)

type excludeFn func(string) bool

// excludingResolver decorates a resolver with an exclusion function that is used to
// filter out entries in the delegate resolver
type excludingResolver struct {
	delegate  FileResolver
	excludeFn excludeFn
}

// NewExcludingResolver create a new resolver which wraps the provided delegate and excludes
// entries based on a provided path exclusion function
func NewExcludingResolver(delegate FileResolver, excludeFn excludeFn) FileResolver {
	return &excludingResolver{
		delegate,
		excludeFn,
	}
}

func (r *excludingResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	if locationMatches(&location, r.excludeFn) {
		return nil, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileContentsByLocation(location)
}

func (r *excludingResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	if locationMatches(&location, r.excludeFn) {
		return FileMetadata{}, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileMetadataByLocation(location)
}

func (r *excludingResolver) HasPath(path string) bool {
	if r.excludeFn(path) {
		return false
	}
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
	l := r.delegate.RelativeFileByPath(location, path)
	if l != nil && locationMatches(l, r.excludeFn) {
		return nil
	}
	return l
}

func (r *excludingResolver) AllLocations() <-chan Location {
	c := make(chan Location)
	go func() {
		defer close(c)
		for location := range r.delegate.AllLocations() {
			if !locationMatches(&location, r.excludeFn) {
				c <- location
			}
		}
	}()
	return c
}

func locationMatches(location *Location, exclusionFn excludeFn) bool {
	return exclusionFn(location.RealPath) || exclusionFn(location.VirtualPath)
}

func filterLocations(locations []Location, err error, exclusionFn excludeFn) ([]Location, error) {
	if err != nil {
		return nil, err
	}
	if exclusionFn != nil {
		for i := 0; i < len(locations); i++ {
			location := &locations[i]
			if locationMatches(location, exclusionFn) {
				locations = append(locations[:i], locations[i+1:]...)
				i--
			}
		}
	}
	return locations, nil
}
