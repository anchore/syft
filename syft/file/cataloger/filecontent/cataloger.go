package filecontent

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

type Config struct {
	// Globs are the file patterns that must be matched for a file to be considered for cataloging.
	Globs []string `yaml:"globs" json:"globs" mapstructure:"globs"`

	// SkipFilesAboveSize is the maximum file size (in bytes) to allow to be considered while cataloging. If the file is larger than this size it will be skipped.
	SkipFilesAboveSize int64 `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
}

type Cataloger struct {
	globs                     []string
	skipFilesAboveSizeInBytes int64
}

func DefaultConfig() Config {
	return Config{
		SkipFilesAboveSize: 250 * intFile.KB,
	}
}

func NewCataloger(cfg Config) *Cataloger {
	return &Cataloger{
		globs:                     cfg.Globs,
		skipFilesAboveSizeInBytes: cfg.SkipFilesAboveSize,
	}
}

func (i *Cataloger) Catalog(_ context.Context, resolver file.Resolver) (map[file.Coordinates]string, error) {
	results := make(map[file.Coordinates]string)
	var locations []file.Location
	var errs error

	locations, err := resolver.FilesByGlob(i.globs...)
	if err != nil {
		return nil, err
	}

	prog := catalogingProgress(int64(len(locations)))

	for _, location := range locations {
		prog.AtomicStage.Set(location.Path())

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			errs = unknown.Append(errs, location, err)
			prog.SetError(err)
			continue
		}

		if i.skipFilesAboveSizeInBytes > 0 && metadata.Size() > i.skipFilesAboveSizeInBytes {
			continue
		}

		result, err := i.catalogLocation(resolver, location)
		if internal.IsErrPathPermission(err) {
			errs = unknown.Append(errs, location, fmt.Errorf("permission error reading file contents: %w", err))
			continue
		}
		if err != nil {
			errs = unknown.Append(errs, location, err)
			continue
		}

		prog.Increment()

		results[location.Coordinates] = result
	}

	log.Debugf("file contents cataloger processed %d files", len(results))

	prog.AtomicStage.Set(fmt.Sprintf("%s files", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, errs
}

func (i *Cataloger) catalogLocation(resolver file.Resolver, location file.Location) (string, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", err
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	buf := &bytes.Buffer{}
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	if _, err = io.Copy(encoder, contentReader); err != nil {
		return "", internal.ErrPath{Context: "content-cataloger", Path: location.RealPath, Err: err}
	}
	// note: it's important to close the reader before reading from the buffer since closing will flush the remaining bytes
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("unable to close base64 encoder: %w", err)
	}

	return buf.String(), nil
}

func catalogingProgress(locations int64) *monitor.TaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "File contents",
		},
		ParentID: monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, locations, "")
}
