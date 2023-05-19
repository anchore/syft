package source

import (
	"io"

	"github.com/anchore/syft/internal/log"
)

func NewDeferredResolverFromSource(creator func() (Source, error)) *DeferredResolver {
	return NewDeferredResolver(func() (FileResolver, error) {
		s, err := creator()
		if err != nil {
			return nil, err
		}

		return s.FileResolver(SquashedScope)
	})
}

func NewDeferredResolver(creator func() (FileResolver, error)) *DeferredResolver {
	return &DeferredResolver{
		creator: creator,
	}
}

type DeferredResolver struct {
	creator  func() (FileResolver, error)
	resolver FileResolver
}

func (d *DeferredResolver) getResolver() (FileResolver, error) {
	if d.resolver == nil {
		resolver, err := d.creator()
		if err != nil {
			return nil, err
		}
		d.resolver = resolver
	}
	return d.resolver, nil
}

func (d *DeferredResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FileContentsByLocation(location)
}

func (d *DeferredResolver) HasPath(s string) bool {
	r, err := d.getResolver()
	if err != nil {
		log.Debug("unable to get resolver: %v", err)
		return false
	}
	return r.HasPath(s)
}

func (d *DeferredResolver) FilesByPath(paths ...string) ([]Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByPath(paths...)
}

func (d *DeferredResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByGlob(patterns...)
}

func (d *DeferredResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByMIMEType(types...)
}

func (d *DeferredResolver) RelativeFileByPath(location Location, path string) *Location {
	r, err := d.getResolver()
	if err != nil {
		return nil
	}
	return r.RelativeFileByPath(location, path)
}

func (d *DeferredResolver) AllLocations() <-chan Location {
	r, err := d.getResolver()
	if err != nil {
		log.Debug("unable to get resolver: %v", err)
		return nil
	}
	return r.AllLocations()
}

func (d *DeferredResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	r, err := d.getResolver()
	if err != nil {
		return FileMetadata{}, err
	}
	return r.FileMetadataByLocation(location)
}

var _ FileResolver = (*DeferredResolver)(nil)
