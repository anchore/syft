package binary

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewBinaryCataloger() *generic.Cataloger {
	return generic.NewCataloger("binary-cataloger").
		WithParserByMimeTypes(parseBinary, internal.ExecutableMIMETypeSet.List()...)
}
