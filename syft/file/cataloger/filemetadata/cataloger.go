package filemetadata

import (
	"fmt"

	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
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
				defer close(ch)
				for _, c := range coordinates {
					locs, err := resolver.FilesByPath(c.RealPath)
					if err != nil {
						log.Warn("unable to get file locations for path %q: %w", c.RealPath, err)
						continue
					}
					for _, loc := range locs {
						ch <- loc
					}
				}
			}()
			return ch
		}()
	}

	prog := metadataCatalogingProgress(int64(len(locations)))
	for location := range locations {
		prog.Increment()
		prog.AtomicStage.Set(location.Path())

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		results[location.Coordinates] = metadata
	}

	log.Debugf("file metadata cataloger processed %d files", prog.Current())

	prog.AtomicStage.Set(fmt.Sprintf("%s locations", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, nil
}

func metadataCatalogingProgress(locations int64) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog file metadata",
			WhileRunning: "Cataloging file metadata",
			OnSuccess:    "Cataloged file metadata",
		},
	}

	return bus.StartCatalogerTask(info, locations, "")
}
