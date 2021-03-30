package file

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/anchore/syft/syft/source"
)

type DigestsCataloger struct {
	hashes []crypto.Hash
}

func NewDigestsCataloger(hashes []crypto.Hash) (*DigestsCataloger, error) {
	return &DigestsCataloger{
		hashes: hashes,
	}, nil
}

func (i *DigestsCataloger) Catalog(resolver source.FileResolver) (map[source.Location][]Digest, error) {
	results := make(map[source.Location][]Digest)
	for location := range resolver.AllLocations() {
		result, err := i.catalogLocation(resolver, location)
		if err != nil {
			return nil, err
		}
		results[location] = result
	}
	return results, nil
}

func (i *DigestsCataloger) catalogLocation(resolver source.FileResolver, location source.Location) ([]Digest, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer contentReader.Close()

	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(i.hashes))
	writers := make([]io.Writer, len(i.hashes))
	for idx, hashObj := range i.hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(io.MultiWriter(writers...), contentReader)
	if err != nil {
		return nil, fmt.Errorf("unable to observe contents of %+v: %+v", location.RealPath, err)
	}

	if size == 0 {
		return make([]Digest, 0), nil
	}

	result := make([]Digest, len(i.hashes))
	// only capture digests when there is content. It is important to do this based on SIZE and not
	// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
	// file type but a body is still allowed.
	for idx, hasher := range hashers {
		result[idx] = Digest{
			Algorithm: DigestAlgorithmName(i.hashes[idx]),
			Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
		}
	}

	return result, nil
}

func DigestAlgorithmName(hash crypto.Hash) string {
	return CleanDigestAlgorithmName(hash.String())
}

func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	return strings.Replace(lower, "-", "", -1)
}
