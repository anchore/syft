package file

import (
	"crypto"
	"slices"

	"github.com/scylladb/go-set/uset"
)

func NormalizeHashes(hashes []crypto.Hash) []crypto.Hash {
	set := uset.New()
	for _, h := range hashes {
		set.Add(uint(h))
	}
	list := set.List()
	slices.Sort(list)
	result := make([]crypto.Hash, len(list))
	for i, v := range list {
		result[i] = crypto.Hash(v)
	}
	return result
}
