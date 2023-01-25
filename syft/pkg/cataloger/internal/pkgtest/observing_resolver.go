package pkgtest

import (
	"fmt"
	"io"
	"sort"

	"github.com/anchore/syft/syft/source"
)

var _ source.FileResolver = (*observingResolver)(nil)

type observingResolver struct {
	decorated             source.FileResolver
	pathQuery             []source.Location
	contentQuery          []source.Location
	emptyPathQueryResults map[string][]string
}

func newObservingResolver(resolver source.FileResolver) *observingResolver {
	return &observingResolver{
		decorated:             resolver,
		pathQuery:             make([]source.Location, 0),
		emptyPathQueryResults: make(map[string][]string),
	}
}

// testing helpers...

//nolint:unused
func (r *observingResolver) observedQuery(path string) bool {
	return r.observedPathQuery(path) || r.observedContentQuery(path)
}

func (r *observingResolver) observedPathQuery(path string) bool {
	for _, loc := range r.pathQuery {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

//nolint:unused
func (r *observingResolver) observedContentQuery(path string) bool {
	for _, loc := range r.pathQuery {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

func (r *observingResolver) observedContentQueries() []string {
	var observed []string
	for _, loc := range r.pathQuery {
		observed = append(observed, loc.RealPath)
	}
	return observed
}

func (r *observingResolver) pruneUnfulfilledPathQueries(ignore map[string][]string, ignorePaths ...string) {
	if ignore == nil {
		return
	}
	// remove any paths that were ignored for specific calls
	for k, v := range ignore {
		results := r.emptyPathQueryResults[k]
		for _, ig := range v {
			for i, result := range results {
				if result == ig {
					results = append(results[:i], results[i+1:]...)
					break
				}
			}
		}
		if len(results) > 0 {
			r.emptyPathQueryResults[k] = results
		} else {
			delete(r.emptyPathQueryResults, k)
		}
	}

	// remove any paths that were ignored for all calls
	for _, ig := range ignorePaths {
		for k, v := range r.emptyPathQueryResults {
			for i, result := range v {
				if result == ig {
					v = append(v[:i], v[i+1:]...)
					break
				}
			}
			if len(v) > 0 {
				r.emptyPathQueryResults[k] = v
			} else {
				delete(r.emptyPathQueryResults, k)
			}
		}
	}
}

func (r *observingResolver) hasUnfulfilledPathRequests() bool {
	return len(r.emptyPathQueryResults) > 0
}

func (r *observingResolver) prettyUnfulfilledPathRequests() string {
	var res string
	var keys []string

	for k := range r.emptyPathQueryResults {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		res += fmt.Sprintf("   %s: %+v\n", k, r.emptyPathQueryResults[k])
	}
	return res
}

// For the file path resolver...

func (r *observingResolver) FilesByPath(paths ...string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByPath(paths...)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByPath"
		results := r.emptyPathQueryResults[key]
		results = append(results, paths...)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) FilesByGlob(patterns ...string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByGlob(patterns...)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByGlob"
		results := r.emptyPathQueryResults[key]
		results = append(results, patterns...)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) FilesByExtension(extension string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByExtension(extension)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByExtension"
		results := r.emptyPathQueryResults[key]
		results = append(results, extension)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) FilesByBasename(filename string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByBasename(filename)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByBasename"
		results := r.emptyPathQueryResults[key]
		results = append(results, filename)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) FilesByBasenameGlob(glob string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByBasenameGlob(glob)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByBasenameGlob"
		results := r.emptyPathQueryResults[key]
		results = append(results, glob)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) FilesByMIMEType(types ...string) ([]source.Location, error) {
	locs, err := r.decorated.FilesByMIMEType(types...)
	r.pathQuery = append(r.pathQuery, locs...)
	if len(locs) == 0 {
		key := "FilesByMIMEType"
		results := r.emptyPathQueryResults[key]
		results = append(results, types...)
		r.emptyPathQueryResults[key] = results
	}
	return locs, err
}

func (r *observingResolver) RelativeFileByPath(l source.Location, path string) *source.Location {
	loc := r.decorated.RelativeFileByPath(l, path)
	if loc != nil {
		r.pathQuery = append(r.pathQuery, *loc)
	} else {
		key := "RelativeFileByPath"
		results := r.emptyPathQueryResults[key]
		results = append(results, path)
		r.emptyPathQueryResults[key] = results
	}
	return loc
}

// For the content resolver methods...

func (r *observingResolver) FileContentsByLocation(location source.Location) (io.ReadCloser, error) {
	reader, err := r.decorated.FileContentsByLocation(location)
	r.contentQuery = append(r.contentQuery, location)
	return reader, err
}

// For the remaining resolver methods...

func (r *observingResolver) AllLocations() <-chan source.Location {
	return r.decorated.AllLocations()
}

func (r *observingResolver) HasPath(s string) bool {
	return r.decorated.HasPath(s)
}

func (r *observingResolver) FileMetadataByLocation(location source.Location) (source.FileMetadata, error) {
	return r.decorated.FileMetadataByLocation(location)
}
