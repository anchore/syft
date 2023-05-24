package file

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"
)

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func NewDigestsFromFile(closer io.ReadCloser, hashes []crypto.Hash) ([]Digest, error) {
	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(hashes))
	writers := make([]io.Writer, len(hashes))
	for idx, hashObj := range hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(io.MultiWriter(writers...), closer)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		return make([]Digest, 0), nil
	}

	result := make([]Digest, len(hashes))
	// only capture digests when there is content. It is important to do this based on SIZE and not
	// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
	// file type but a body is still allowed.
	for idx, hasher := range hashers {
		result[idx] = Digest{
			Algorithm: DigestAlgorithmName(hashes[idx]),
			Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
		}
	}

	return result, nil
}

func Hashers(names ...string) ([]crypto.Hash, error) {
	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[DigestAlgorithmName(h)] = h
	}

	var hashers []crypto.Hash
	for _, hashStr := range names {
		hashObj, ok := supportedHashAlgorithms[CleanDigestAlgorithmName(hashStr)]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashers = append(hashers, hashObj)
	}
	return hashers, nil
}

func DigestAlgorithmName(hash crypto.Hash) string {
	return CleanDigestAlgorithmName(hash.String())
}

func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	return strings.ReplaceAll(lower, "-", "")
}
