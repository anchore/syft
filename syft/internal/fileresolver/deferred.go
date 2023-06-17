package fileresolver

import (
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*Deferred)(nil)

func NewDeferred(creator func() (file.Resolver, error)) *Deferred {
	return &Deferred{
		creator: creator,
	}
}

type Deferred struct {
	creator  func() (file.Resolver, error)
	resolver file.Resolver
}

func (d *Deferred) getResolver() (file.Resolver, error) {
	if d.resolver == nil {
		resolver, err := d.creator()
		if err != nil {
			return nil, err
		}
		d.resolver = resolver
	}
	return d.resolver, nil
}

func (d *Deferred) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FileContentsByLocation(location)
}

func (d *Deferred) HasPath(s string) bool {
	r, err := d.getResolver()
	if err != nil {
		log.Debug("unable to get resolver: %v", err)
		return false
	}
	return r.HasPath(s)
}

func (d *Deferred) FilesByPath(paths ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByPath(paths...)
}

func (d *Deferred) FilesByGlob(patterns ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByGlob(patterns...)
}

func (d *Deferred) FilesByMIMEType(types ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByMIMEType(types...)
}

func (d *Deferred) RelativeFileByPath(location file.Location, path string) *file.Location {
	r, err := d.getResolver()
	if err != nil {
		return nil
	}
	return r.RelativeFileByPath(location, path)
}

func (d *Deferred) AllLocations() <-chan file.Location {
	r, err := d.getResolver()
	if err != nil {
		log.Debug("unable to get resolver: %v", err)
		return nil
	}
	return r.AllLocations()
}

func (d *Deferred) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	r, err := d.getResolver()
	if err != nil {
		return file.Metadata{}, err
	}
	return r.FileMetadataByLocation(location)
}
