package fileresolver

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/file"
)

type excludeFn func(string) bool

// excluding decorates a resolver with an exclusion function that is used to
// filter out entries in the delegate resolver
type excluding struct {
	delegate  file.Resolver
	excludeFn excludeFn
}

// NewExcludingDecorator create a new resolver which wraps the provided delegate and excludes
// entries based on a provided path exclusion function
func NewExcludingDecorator(delegate file.Resolver, excludeFn excludeFn) file.Resolver {
	return &excluding{
		delegate,
		excludeFn,
	}
}

func (r *excluding) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if locationMatches(&location, r.excludeFn) {
		return nil, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileContentsByLocation(location)
}

func (r *excluding) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	if locationMatches(&location, r.excludeFn) {
		return file.Metadata{}, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileMetadataByLocation(location)
}

func (r *excluding) HasPath(path string) bool {
	if r.excludeFn(path) {
		return false
	}
	return r.delegate.HasPath(path)
}

func (r *excluding) FilesByPath(paths ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByPath(paths...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excluding) FilesByGlob(patterns ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByGlob(patterns...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excluding) FilesByMIMEType(types ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByMIMEType(types...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excluding) RelativeFileByPath(location file.Location, path string) *file.Location {
	l := r.delegate.RelativeFileByPath(location, path)
	if l != nil && locationMatches(l, r.excludeFn) {
		return nil
	}
	return l
}

func (r *excluding) AllLocations() <-chan file.Location {
	c := make(chan file.Location)
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

func locationMatches(location *file.Location, exclusionFn excludeFn) bool {
	return exclusionFn(location.RealPath) || exclusionFn(location.VirtualPath)
}

func filterLocations(locations []file.Location, err error, exclusionFn excludeFn) ([]file.Location, error) {
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
