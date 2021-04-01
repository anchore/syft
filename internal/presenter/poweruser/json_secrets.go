package poweruser

import (
	"sort"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type JSONSecrets struct {
	Location source.Location     `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}

func NewJSONSecrets(data map[source.Location][]file.SearchResult) []JSONSecrets {
	results := make([]JSONSecrets, 0)
	for location, secrets := range data {
		results = append(results, JSONSecrets{
			Location: location,
			Secrets:  secrets,
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Location.RealPath != results[j].Location.RealPath {
			return results[i].Location.VirtualPath < results[j].Location.VirtualPath
		}
		return false
	})
	return results
}
