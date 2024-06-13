/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
package source

import (
	"errors"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

type Source interface {
	artifact.Identifiable
	FileResolver(Scope) (file.Resolver, error)
	Describe() Description
	io.Closer
}

type emptySource struct {
	description Description
}

func FromDescription(d Description) Source {
	return &emptySource{
		description: d,
	}
}

func (e emptySource) ID() artifact.ID {
	return artifact.ID(e.description.ID)
}

func (e emptySource) FileResolver(_ Scope) (file.Resolver, error) {
	return nil, errors.New("no file resolver available for description-only source")
}

func (e emptySource) Describe() Description {
	return e.description
}

func (e emptySource) Close() error {
	return nil // no-op
}

func (e emptySource) Compare(other emptySource) int {
	return e.description.Compare(other.description)
}
func (e emptySource) TryCompare(other any) (bool, int) {
	if other, exists := other.(emptySource); exists {
		return true, e.Compare(other)
	}
	return false, 0
}
