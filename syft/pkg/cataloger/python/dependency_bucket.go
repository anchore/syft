package python

import (
	"sort"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// resolvePackagesBySiteAndName indexes packages by the site-packages directory
// they were installed into, then by distribution name, and returns both the
// buckets and the distinct site-packages directories in a stable order.
//
// The previous implementation keyed strictly by (site-packages dir, name) and
// kept one package per key. A distribution can be installed both top-level and
// vendored inside another distribution's wheel, and when neither copy sits under
// a site-packages or dist-packages directory, deriveSitePackageDir returns "" for
// both. Those two copies then collided on the same key and the map silently kept
// whichever was catalogued last, so a package resolving a dependency by name was
// linked to an arbitrary copy and the resulting dependency graph changed between
// scans of an unchanged tree.
//
// Each package therefore additionally carries its own evidence directory in the
// key, which is unique per installation. Iterating the keys in sorted order also
// makes bucketing reproducible, which the map-of-maps version was not.
//
// See https://github.com/anchore/syft/issues/5357
func resolvePackagesBySiteAndName(pkgs []pkg.Package) ([]map[string]pkg.Package, []string) {
	type bucketKey struct {
		site     string
		evidence string
	}

	byBucket := make(map[bucketKey]map[string]pkg.Package)
	sites := make(map[string]struct{})

	for _, p := range pkgs {
		site := deriveSitePackageDir(p)
		sites[site] = struct{}{}

		key := bucketKey{site: site, evidence: deriveEvidenceDir(p)}
		if byBucket[key] == nil {
			byBucket[key] = make(map[string]pkg.Package)
		}
		byBucket[key][p.Name] = p
	}

	// iterate the keys in a stable order so the bucketing of a given tree is
	// reproducible regardless of map iteration order
	keys := make([]bucketKey, 0, len(byBucket))
	for key := range byBucket {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].site != keys[j].site {
			return keys[i].site < keys[j].site
		}
		return keys[i].evidence < keys[j].evidence
	})

	buckets := make([]map[string]pkg.Package, 0, len(keys))
	for _, key := range keys {
		buckets = append(buckets, byBucket[key])
	}

	sitePackagesDirs := make([]string, 0, len(sites))
	for site := range sites {
		sitePackagesDirs = append(sitePackagesDirs, site)
	}
	sort.Strings(sitePackagesDirs)

	return buckets, sitePackagesDirs
}

// deriveEvidenceDir returns the directory holding a package's primary evidence,
// used to keep separate installations of the same distribution apart.
func deriveEvidenceDir(p pkg.Package) string {
	for _, l := range packagePrimaryLocations(p) {
		if dir := parentDir(l.RealPath); dir != "" {
			return dir
		}
	}
	for _, l := range p.Locations.ToSlice() {
		if dir := parentDir(l.RealPath); dir != "" {
			return dir
		}
	}
	return ""
}

func parentDir(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return ""
	}
	return path[:idx]
}
