package artifact

import (
	"fmt"
	"github.com/anchore/syft/syft/sort"
	"github.com/mitchellh/hashstructure/v2"
)

// ID represents a unique value for each package added to a package catalog.
type ID string

func (id ID) Compare(other ID) int {
	return sort.CompareOrd(string(id), string(other))
}

type Identifiable interface {
	sort.TryComparable
	ID() ID
}

func IDByHash(obj interface{}) (ID, error) {
	f, err := hashstructure.Hash(obj, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", fmt.Errorf("could not build ID for object=%+v: %w", obj, err)
	}

	return ID(fmt.Sprintf("%016x", f)), nil
}
