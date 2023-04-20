package source

import (
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*DeferredResolver)(nil)

func NewDeferredResolverFromSource(creator func() (Source, error)) *DeferredResolver {
	return NewDeferredResolver(func() (file.Resolver, error) {
		s, err := creator()
		if err != nil {
			return nil, err
		}

		return s.FileResolver(SquashedScope)
	})
}

func NewDeferredResolver(creator func() (file.Resolver, error)) *DeferredResolver {
	return &DeferredResolver{
		creator: creator,
	}
}

type DeferredResolver struct {
	creator  func() (file.Resolver, error)
	resolver file.Resolver
}

func (d *DeferredResolver) getResolver() (file.Resolver, error) {
	if d.resolver == nil {
		resolver, err := d.creator()
		if err != nil {
			return nil, err
		}
		d.resolver = resolver
	}
	return d.resolver, nil
}

func (d *DeferredResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
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

func (d *DeferredResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByPath(paths...)
}

func (d *DeferredResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByGlob(patterns...)
}

func (d *DeferredResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	r, err := d.getResolver()
	if err != nil {
		return nil, err
	}
	return r.FilesByMIMEType(types...)
}

func (d *DeferredResolver) RelativeFileByPath(location file.Location, path string) *Location {
	r, err := d.getResolver()
	if err != nil {
		return nil
	}
	return r.RelativeFileByPath(location, path)
}

func (d *DeferredResolver) AllLocations() <-chan file.Location {
	r, err := d.getResolver()
	if err != nil {
		log.Debug("unable to get resolver: %v", err)
		return nil
	}
	return r.AllLocations()
}

func (d *DeferredResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	r, err := d.getResolver()
	if err != nil {
		return file.Metadata{}, err
	}
	return r.FileMetadataByLocation(location)
}
