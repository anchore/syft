package fileresolver

import (
	"context"
	"io"

	"github.com/anchore/syft/syft/file"
)

var _ file.WritableResolver = (*Empty)(nil)

type Empty struct{}

func (e Empty) FileContentsByLocation(_ file.Location) (io.ReadCloser, error) {
	return nil, nil
}

func (e Empty) HasPath(_ string) bool {
	return false
}

func (e Empty) FilesByPath(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (e Empty) FilesByGlob(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (e Empty) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (e Empty) RelativeFileByPath(_ file.Location, _ string) *file.Location {
	return nil
}

func (e Empty) AllLocations(_ context.Context) <-chan file.Location {
	return nil
}

func (e Empty) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{}, nil
}

func (e Empty) Write(_ file.Location, _ io.Reader) error {
	return nil
}
