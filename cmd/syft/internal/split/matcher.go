package split

import (
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// MatchPackages finds packages in the collection that match the given queries.
// Match order (first match wins):
// 1. Exact package ID match
// 2. Exact PURL match or PURL prefix match
// 3. Case-insensitive name match
// 4. name@version format match
func MatchPackages(collection *pkg.Collection, queries []string) []pkg.Package {
	if collection == nil || len(queries) == 0 {
		return nil
	}

	// build indexes for efficient lookups
	byID := make(map[artifact.ID]pkg.Package)
	byPURL := make(map[string]pkg.Package)
	byNameLower := make(map[string][]pkg.Package)
	byNameVersion := make(map[string]pkg.Package)

	for p := range collection.Enumerate() {
		byID[p.ID()] = p
		if p.PURL != "" {
			byPURL[p.PURL] = p
		}
		nameLower := strings.ToLower(p.Name)
		byNameLower[nameLower] = append(byNameLower[nameLower], p)
		nameVersion := strings.ToLower(p.Name + "@" + p.Version)
		byNameVersion[nameVersion] = p
	}

	// track matched packages to avoid duplicates
	matched := make(map[artifact.ID]pkg.Package)

	for _, query := range queries {
		// 1. exact package ID match
		if p, ok := byID[artifact.ID(query)]; ok {
			matched[p.ID()] = p
			continue
		}

		// 2. exact PURL match
		if p, ok := byPURL[query]; ok {
			matched[p.ID()] = p
			continue
		}

		// 2b. PURL prefix match (e.g., "pkg:apk/alpine/musl" matches "pkg:apk/alpine/musl@1.2.2")
		if strings.HasPrefix(query, "pkg:") {
			for purl, p := range byPURL {
				if strings.HasPrefix(purl, query) {
					matched[p.ID()] = p
				}
			}
			if len(matched) > 0 {
				continue
			}
		}

		queryLower := strings.ToLower(query)

		// 3. case-insensitive name match
		if pkgs, ok := byNameLower[queryLower]; ok {
			for _, p := range pkgs {
				matched[p.ID()] = p
			}
			continue
		}

		// 4. name@version format match
		if p, ok := byNameVersion[queryLower]; ok {
			matched[p.ID()] = p
			continue
		}
	}

	// convert map to slice
	result := make([]pkg.Package, 0, len(matched))
	for _, p := range matched {
		result = append(result, p)
	}

	// sort for stable output
	pkg.Sort(result)
	return result
}
