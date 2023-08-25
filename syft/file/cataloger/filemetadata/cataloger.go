package filemetadata

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
)

type Cataloger struct {
}

func NewCataloger() *Cataloger {
	return &Cataloger{}
}

func (i *Cataloger) Catalog(resolver file.Resolver, coordinates ...file.Coordinates) (map[file.Coordinates]file.Metadata, error) {
	results := make(map[file.Coordinates]file.Metadata)
	var locations <-chan file.Location

	if len(coordinates) == 0 {
		locations = resolver.AllLocations()
	} else {
		locations = func() <-chan file.Location {
			ch := make(chan file.Location)
			go func() {
				close(ch)
				for _, c := range coordinates {
					ch <- file.NewLocationFromCoordinates(c)
				}
			}()
			return ch
		}()
	}

	stage, prog := metadataCatalogingProgress(int64(len(locations)))
	for location := range locations {
		stage.Current = location.RealPath
		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		results[location.Coordinates] = metadata
		prog.Increment()
	}
	log.Debugf("file metadata cataloger processed %d files", prog.Current())
	prog.SetCompleted()
	return results, nil
}

func metadataCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := progress.NewManual(locations)

	bus.Publish(partybus.Event{
		Type: event.FileMetadataCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
