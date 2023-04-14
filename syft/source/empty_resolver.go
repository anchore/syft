package source

import (
	"io"
)

type EmptyResolver struct{}

func (e EmptyResolver) FileContentsByLocation(_ Location) (io.ReadCloser, error) {
	return nil, nil
}

func (e EmptyResolver) HasPath(_ string) bool {
	return false
}

func (e EmptyResolver) FilesByPath(_ ...string) ([]Location, error) {
	return nil, nil
}

func (e EmptyResolver) FilesByGlob(_ ...string) ([]Location, error) {
	return nil, nil
}

func (e EmptyResolver) FilesByMIMEType(_ ...string) ([]Location, error) {
	return nil, nil
}

func (e EmptyResolver) RelativeFileByPath(_ Location, _ string) *Location {
	return nil
}

func (e EmptyResolver) AllLocations() <-chan Location {
	return nil
}

func (e EmptyResolver) FileMetadataByLocation(_ Location) (FileMetadata, error) {
	return FileMetadata{}, nil
}

func (e EmptyResolver) Write(_ Location, _ io.Reader) error {
	return nil
}

var _ WritableFileResolver = (*EmptyResolver)(nil)
