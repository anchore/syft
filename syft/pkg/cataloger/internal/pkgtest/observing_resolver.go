// Package pkgtest provides test helpers for cataloger and parser testing,
// including resolver decorators that track file access patterns.
package pkgtest

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ObservingResolver)(nil)

// ObservingResolver wraps a file.Resolver to observe and track all file access patterns.
// it records what paths were queried, what was returned, and what file contents were read.
// this is useful for validating that catalogers use appropriate glob patterns and don't over-read files.
type ObservingResolver struct {
	decorated          file.Resolver
	pathQueries        map[string][]string // method name -> list of query patterns
	pathResponses      []file.Location     // all locations successfully returned
	contentQueries     []file.Location     // all locations whose content was read
	emptyPathResponses map[string][]string // method name -> paths that returned empty results
}

// NewObservingResolver creates a new ObservingResolver that wraps the given resolver.
func NewObservingResolver(resolver file.Resolver) *ObservingResolver {
	return &ObservingResolver{
		decorated:          resolver,
		pathQueries:        make(map[string][]string),
		pathResponses:      make([]file.Location, 0),
		contentQueries:     make([]file.Location, 0),
		emptyPathResponses: make(map[string][]string),
	}
}

// ===== Test Assertion Helpers =====
// these methods are used by tests to validate expected file access patterns.

// ObservedPathQuery checks if a specific path pattern was queried.
func (r *ObservingResolver) ObservedPathQuery(input string) bool {
	for _, queries := range r.pathQueries {
		for _, query := range queries {
			if query == input {
				return true
			}
		}
	}
	return false
}

// ObservedPathResponses checks if a specific path was returned in any response.
func (r *ObservingResolver) ObservedPathResponses(path string) bool {
	for _, loc := range r.pathResponses {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

// ObservedContentQueries checks if a specific file's content was read.
func (r *ObservingResolver) ObservedContentQueries(path string) bool {
	for _, loc := range r.contentQueries {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

// AllContentQueries returns a deduplicated list of all file paths whose content was read.
func (r *ObservingResolver) AllContentQueries() []string {
	observed := strset.New()
	for _, loc := range r.contentQueries {
		observed.Add(loc.RealPath)
	}
	return observed.List()
}

// AllPathQueries returns all path query patterns grouped by method name.
func (r *ObservingResolver) AllPathQueries() map[string][]string {
	return r.pathQueries
}

// PruneUnfulfilledPathResponses removes specified paths from the unfulfilled requests tracking.
// ignore maps method names to paths that should be ignored for that method.
// ignorePaths lists paths that should be ignored for all methods.
func (r *ObservingResolver) PruneUnfulfilledPathResponses(ignore map[string][]string, ignorePaths ...string) {
	// remove paths ignored for specific methods
	for methodName, pathsToIgnore := range ignore {
		r.emptyPathResponses[methodName] = removeStrings(r.emptyPathResponses[methodName], pathsToIgnore)
		if len(r.emptyPathResponses[methodName]) == 0 {
			delete(r.emptyPathResponses, methodName)
		}
	}

	// remove paths ignored for all methods
	if len(ignorePaths) > 0 {
		for methodName := range r.emptyPathResponses {
			r.emptyPathResponses[methodName] = removeStrings(r.emptyPathResponses[methodName], ignorePaths)
			if len(r.emptyPathResponses[methodName]) == 0 {
				delete(r.emptyPathResponses, methodName)
			}
		}
	}
}

// HasUnfulfilledPathRequests returns true if there are any paths that were queried but returned empty.
func (r *ObservingResolver) HasUnfulfilledPathRequests() bool {
	return len(r.emptyPathResponses) > 0
}

// PrettyUnfulfilledPathRequests returns a formatted string of all unfulfilled path requests.
func (r *ObservingResolver) PrettyUnfulfilledPathRequests() string {
	if len(r.emptyPathResponses) == 0 {
		return ""
	}

	var keys []string
	for k := range r.emptyPathResponses {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var result string
	for _, k := range keys {
		result += fmt.Sprintf("   %s: %+v\n", k, r.emptyPathResponses[k])
	}
	return result
}

// removeStrings removes all occurrences of toRemove from slice.
func removeStrings(slice []string, toRemove []string) []string {
	if len(toRemove) == 0 {
		return slice
	}

	// create a set for O(1) lookup
	removeSet := make(map[string]bool)
	for _, s := range toRemove {
		removeSet[s] = true
	}

	// filter the slice
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !removeSet[s] {
			result = append(result, s)
		}
	}
	return result
}

// ===== Internal Tracking Helpers =====

// recordQuery records a path query for a given method.
func (r *ObservingResolver) recordQuery(methodName string, queries ...string) {
	r.pathQueries[methodName] = append(r.pathQueries[methodName], queries...)
}

// recordResponses records successful path responses and tracks any unfulfilled queries.
func (r *ObservingResolver) recordResponses(methodName string, locs []file.Location, queriedPaths ...string) {
	r.pathResponses = append(r.pathResponses, locs...)

	// track paths that returned no results
	if len(locs) == 0 && len(queriedPaths) > 0 {
		r.emptyPathResponses[methodName] = append(r.emptyPathResponses[methodName], queriedPaths...)
	}
}

// ===== file.Resolver Implementation =====
// these methods delegate to the wrapped resolver while recording observations.

// FilesByPath returns files matching the given paths.
func (r *ObservingResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	const methodName = "FilesByPath"
	r.recordQuery(methodName, paths...)

	locs, err := r.decorated.FilesByPath(paths...)
	r.recordResponses(methodName, locs, paths...)

	return locs, err
}

// FilesByGlob returns files matching the given glob patterns.
func (r *ObservingResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	const methodName = "FilesByGlob"
	r.recordQuery(methodName, patterns...)

	locs, err := r.decorated.FilesByGlob(patterns...)
	r.recordResponses(methodName, locs, patterns...)

	return locs, err
}

// FilesByMIMEType returns files matching the given MIME types.
func (r *ObservingResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	const methodName = "FilesByMIMEType"
	r.recordQuery(methodName, types...)

	locs, err := r.decorated.FilesByMIMEType(types...)
	r.recordResponses(methodName, locs, types...)

	return locs, err
}

// RelativeFileByPath returns a file at a path relative to the given location.
func (r *ObservingResolver) RelativeFileByPath(location file.Location, path string) *file.Location {
	const methodName = "RelativeFileByPath"
	r.recordQuery(methodName, path)

	loc := r.decorated.RelativeFileByPath(location, path)

	if loc != nil {
		r.pathResponses = append(r.pathResponses, *loc)
	} else {
		r.emptyPathResponses[methodName] = append(r.emptyPathResponses[methodName], path)
	}

	return loc
}

// FileContentsByLocation returns a reader for the contents of the file at the given location.
func (r *ObservingResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	r.contentQueries = append(r.contentQueries, location)
	return r.decorated.FileContentsByLocation(location)
}

// AllLocations returns all file locations known to the resolver.
func (r *ObservingResolver) AllLocations(ctx context.Context) <-chan file.Location {
	return r.decorated.AllLocations(ctx)
}

// HasPath returns true if the resolver knows about the given path.
func (r *ObservingResolver) HasPath(path string) bool {
	return r.decorated.HasPath(path)
}

// FileMetadataByLocation returns metadata for the file at the given location.
func (r *ObservingResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return r.decorated.FileMetadataByLocation(location)
}
