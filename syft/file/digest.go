package file

import "strings"

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func (dig Digest) Compare(other Digest) int {
	if i := strings.Compare(dig.Algorithm, other.Algorithm); i != 0 {
		return i
	}
	return strings.Compare(dig.Value, other.Value)
}
