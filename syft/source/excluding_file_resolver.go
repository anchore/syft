package source

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/file"
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

func (r *excludingResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if locationMatches(&location, r.excludeFn) {
		return nil, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileContentsByLocation(location)
}

func (r *excludingResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	if locationMatches(&location, r.excludeFn) {
		return file.Metadata{}, fmt.Errorf("no such location: %+v", location.RealPath)
	}
	return r.delegate.FileMetadataByLocation(location)
}

func (r *excludingResolver) HasPath(path string) bool {
	if r.excludeFn(path) {
		return false
	}
	return r.delegate.HasPath(path)
}

func (r *excludingResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByPath(paths...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByGlob(patterns...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByMIMEType(types...)
	return filterLocations(locations, err, r.excludeFn)
}

func (r *excludingResolver) RelativeFileByPath(location file.Location, path string) *file.Location {
	l := r.delegate.RelativeFileByPath(location, path)
	if l != nil && locationMatches(l, r.excludeFn) {
		return nil
	}
	return l
}

func (r *excludingResolver) AllLocations() <-chan file.Location {
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
	return exclusionFn(location.RealPath) || exclusionFn(location.AccessPath)
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
