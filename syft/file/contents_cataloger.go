package file

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

type ContentsCataloger struct {
	globs                     []string
	skipFilesAboveSizeInBytes int64
}

func NewContentsCataloger(globs []string, skipFilesAboveSize int64) (*ContentsCataloger, error) {
	return &ContentsCataloger{
		globs:                     globs,
		skipFilesAboveSizeInBytes: skipFilesAboveSize,
	}, nil
}

func (i *ContentsCataloger) Catalog(resolver source.FileResolver) (map[source.Coordinates]string, error) {
	results := make(map[source.Coordinates]string)
	var locations []source.Location

	locations, err := resolver.FilesByGlob(i.globs...)
	if err != nil {
		return nil, err
	}
	for _, location := range locations {
		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		if i.skipFilesAboveSizeInBytes > 0 && metadata.Size > i.skipFilesAboveSizeInBytes {
			continue
		}

		result, err := i.catalogLocation(resolver, location)
		if internal.IsErrPathPermission(err) {
			log.Debugf("file contents cataloger skipping - %+v", err)
			continue
		}
		if err != nil {
			return nil, err
		}
		results[location.Coordinates] = result
	}
	log.Debugf("file contents cataloger processed %d files", len(results))

	return results, nil
}

func (i *ContentsCataloger) catalogLocation(resolver source.FileResolver, location source.Location) (string, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", err
	}
	defer internal.CloseAndLogError(contentReader, location.VirtualPath)

	buf := &bytes.Buffer{}
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	if _, err = io.Copy(encoder, contentReader); err != nil {
		return "", internal.ErrPath{Context: "contents-cataloger", Path: location.RealPath, Err: err}
	}
	// note: it's important to close the reader before reading from the buffer since closing will flush the remaining bytes
	if err := encoder.Close(); err != nil {
		return "", fmt.Errorf("unable to close base64 encoder: %w", err)
	}

	return buf.String(), nil
}
