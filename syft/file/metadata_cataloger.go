package file

import (
	"github.com/anchore/syft/syft/source"
)

type MetadataCataloger struct {
	resolver source.FileResolver
}

func NewMetadataCataloger(resolver source.FileResolver) *MetadataCataloger {
	return &MetadataCataloger{
		resolver: resolver,
	}
}

func (i *MetadataCataloger) Catalog() (map[source.Location]source.FileMetadata, error) {
	results := make(map[source.Location]source.FileMetadata)
	for location := range i.resolver.AllLocations() {
		metadata, err := i.resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		results[location] = metadata
	}
	return results, nil
}
