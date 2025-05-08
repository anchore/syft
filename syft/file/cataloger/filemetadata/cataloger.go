package filemetadata

import (
	"context"
	"fmt"

	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

type Cataloger struct {
}

func NewCataloger() *Cataloger {
	return &Cataloger{}
}

func (i *Cataloger) Catalog(ctx context.Context, resolver file.Resolver, coordinates ...file.Coordinates) (map[file.Coordinates]file.Metadata, error) {
	var errs error
	results := make(map[file.Coordinates]file.Metadata)
	var locations <-chan file.Location
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if len(coordinates) == 0 {
		locations = resolver.AllLocations(ctx)
	} else {
		locations = func() <-chan file.Location {
			ch := make(chan file.Location)
			go func() {
				defer close(ch)
				for _, c := range coordinates {
					locs, err := resolver.FilesByPath(c.RealPath)
					if err != nil {
						errs = unknown.Append(errs, c, err)
						continue
					}
					for _, loc := range locs {
						select {
						case <-ctx.Done():
							return
						case ch <- loc:
							continue
						}
					}
				}
			}()
			return ch
		}()
	}

	prog := catalogingProgress(-1)
	for location := range locations {
		prog.AtomicStage.Set(location.Path())

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			prog.SetError(err)
			return nil, err
		}

		prog.Increment()

		results[location.Coordinates] = metadata
	}

	log.Debugf("file metadata cataloger processed %d files", prog.Current())

	prog.AtomicStage.Set(fmt.Sprintf("%s locations", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, errs
}

func catalogingProgress(locations int64) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "File metadata",
		},
		ParentID: monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, locations, "")
}
