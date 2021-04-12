package poweruser

import (
	"sort"

	"github.com/anchore/syft/syft/source"
)

type JSONFileContents struct {
	Location source.Location `json:"location"`
	Contents string          `json:"contents"`
}

func NewJSONFileContents(data map[source.Location]string) []JSONFileContents {
	results := make([]JSONFileContents, 0)
	for location, contents := range data {
		results = append(results, JSONFileContents{
			Location: location,
			Contents: contents,
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Location.RealPath == results[j].Location.RealPath {
			return results[i].Location.VirtualPath < results[j].Location.VirtualPath
		}
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results
}
