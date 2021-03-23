package file

import (
	"github.com/anchore/syft/syft/source"
)

type MetadataCataloger struct {
}

func NewMetadataCataloger() *MetadataCataloger {
	return &MetadataCataloger{}
}

func (i *MetadataCataloger) Catalog(resolver source.FileResolver) (map[source.Location]source.FileMetadata, error) {
	results := make(map[source.Location]source.FileMetadata)
	for location := range resolver.AllLocations() {
		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		results[location] = metadata
	}
	return results, nil
}
