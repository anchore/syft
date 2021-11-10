package poweruser

import (
	"sort"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type JSONFileClassifications struct {
	Location       source.Coordinates  `json:"location"`
	Classification file.Classification `json:"classification"`
}

func NewJSONFileClassifications(data map[source.Coordinates][]file.Classification) []JSONFileClassifications {
	results := make([]JSONFileClassifications, 0)
	for coordinates, classifications := range data {
		for _, classification := range classifications {
			results = append(results, JSONFileClassifications{
				Location:       coordinates,
				Classification: classification,
			})
		}
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results
}
