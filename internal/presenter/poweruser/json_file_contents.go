package poweruser

import (
	"sort"

	"github.com/anchore/syft/syft/source"
)

type JSONFileContents struct {
	Location source.Coordinates `json:"location"`
	Contents string             `json:"contents"`
}

func NewJSONFileContents(data map[source.Coordinates]string) []JSONFileContents {
	results := make([]JSONFileContents, 0)
	for coordinates, contents := range data {
		results = append(results, JSONFileContents{
			Location: coordinates,
			Contents: contents,
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results
}
