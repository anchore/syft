package file

import "github.com/anchore/syft/syft/sort"

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func (dig Digest) Compare(other Digest) int {
	if i := sort.CompareOrd(dig.Algorithm, other.Algorithm); i != 0 {
		return i
	}
	return sort.CompareOrd(dig.Value, other.Value)
}
