package poweruser

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/source"
)

type JSONFileMetadata struct {
	Location source.Location       `json:"location"`
	Metadata JSONFileMetadataEntry `json:"metadata"`
}

type JSONFileMetadataEntry struct {
	Mode    int             `json:"mode"`
	Type    source.FileType `json:"type"`
	UserID  int             `json:"userID"`
	GroupID int             `json:"groupID"`
	Digests []file.Digest   `json:"digests"`
}

func NewJSONFileMetadata(data map[source.Location]source.FileMetadata, digests map[source.Location][]file.Digest) ([]JSONFileMetadata, error) {
	results := make([]JSONFileMetadata, 0)
	for location, metadata := range data {
		mode, err := strconv.Atoi(fmt.Sprintf("%o", metadata.Mode))
		if err != nil {
			return nil, fmt.Errorf("invalid mode found in file catalog @ location=%+v mode=%q: %w", location, metadata.Mode, err)
		}

		digestResults := make([]file.Digest, 0)
		if digestsForLocation, exists := digests[location]; exists {
			digestResults = digestsForLocation
		}

		results = append(results, JSONFileMetadata{
			Location: location,
			Metadata: JSONFileMetadataEntry{
				Mode:    mode,
				Type:    metadata.Type,
				UserID:  metadata.UserID,
				GroupID: metadata.GroupID,
				Digests: digestResults,
			},
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Location.RealPath != results[j].Location.RealPath {
			return results[i].Location.VirtualPath < results[j].Location.VirtualPath
		}
		return false
	})
	return results, nil
}
