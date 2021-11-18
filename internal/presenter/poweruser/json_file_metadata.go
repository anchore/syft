package poweruser

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/source"
)

type JSONFileMetadata struct {
	Location source.Coordinates    `json:"location"`
	Metadata JSONFileMetadataEntry `json:"metadata"`
}

type JSONFileMetadataEntry struct {
	Mode            int             `json:"mode"`
	Type            source.FileType `json:"type"`
	LinkDestination string          `json:"linkDestination,omitempty"`
	UserID          int             `json:"userID"`
	GroupID         int             `json:"groupID"`
	Digests         []file.Digest   `json:"digests,omitempty"`
	MIMEType        string          `json:"mimeType"`
}

func NewJSONFileMetadata(data map[source.Coordinates]source.FileMetadata, digests map[source.Coordinates][]file.Digest) ([]JSONFileMetadata, error) {
	results := make([]JSONFileMetadata, 0)
	for coordinates, metadata := range data {
		mode, err := strconv.Atoi(fmt.Sprintf("%o", metadata.Mode))
		if err != nil {
			return nil, fmt.Errorf("invalid mode found in file catalog @ location=%+v mode=%q: %w", coordinates, metadata.Mode, err)
		}

		var digestResults []file.Digest
		if digestsForLocation, exists := digests[coordinates]; exists {
			digestResults = digestsForLocation
		}

		results = append(results, JSONFileMetadata{
			Location: coordinates,
			Metadata: JSONFileMetadataEntry{
				Mode:            mode,
				Type:            metadata.Type,
				LinkDestination: metadata.LinkDestination,
				UserID:          metadata.UserID,
				GroupID:         metadata.GroupID,
				Digests:         digestResults,
				MIMEType:        metadata.MIMEType,
			},
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Location.RealPath < results[j].Location.RealPath
	})
	return results, nil
}
