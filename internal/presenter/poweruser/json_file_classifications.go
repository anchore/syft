package poweruser

import (
	"sort"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type JSONFileClassifications struct {
	Location       source.Location     `json:"location"`
	Classification file.Classification `json:"classification"`
}

func NewJSONFileClassifications(data map[source.Location][]file.Classification) []JSONFileClassifications {
	results := make([]JSONFileClassifications, 0)
	for location, classifications := range data {
		for _, classification := range classifications {
			results = append(results, JSONFileClassifications{
				Location:       location,
				Classification: classification,
			})
		}
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
