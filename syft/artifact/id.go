package artifact

import (
	"fmt"

	"github.com/gohugoio/hashstructure"
)

// ID represents a unique value for each package added to a package catalog.
type ID string

type Identifiable interface {
	ID() ID
}

func IDByHash(obj interface{}) (ID, error) {
	f, err := hashstructure.Hash(obj, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", fmt.Errorf("could not build ID for object=%+v: %w", obj, err)
	}

	return ID(fmt.Sprintf("%016x", f)), nil
}
