package file

import (
	"context"
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/anchore/go-sync"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
)

func supportedHashAlgorithms() []crypto.Hash {
	return []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}
}

func NewDigestsFromFile(ctx context.Context, closer io.ReadCloser, hashes []crypto.Hash) ([]file.Digest, error) {
	hashes = NormalizeHashes(hashes)
	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(hashes))
	writers := make([]io.Writer, len(hashes))
	for idx, hashObj := range hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(sync.ParallelWriter(ctx, cataloging.ExecutorCPU, writers...), closer)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		return make([]file.Digest, 0), nil
	}

	result := make([]file.Digest, len(hashes))
	// only capture digests when there is content. It is important to do this based on SIZE and not
	// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
	// file type but a body is still allowed.
	for idx, hasher := range hashers {
		result[idx] = file.Digest{
			Algorithm: CleanDigestAlgorithmName(hashes[idx].String()),
			Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
		}
	}

	return result, nil
}

func Hashers(names ...string) ([]crypto.Hash, error) {
	hashByName := make(map[string]crypto.Hash)
	for _, h := range supportedHashAlgorithms() {
		hashByName[CleanDigestAlgorithmName(h.String())] = h
	}

	var hashers []crypto.Hash
	for _, hashStr := range names {
		hashObj, ok := hashByName[CleanDigestAlgorithmName(hashStr)]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashers = append(hashers, hashObj)
	}
	return NormalizeHashes(hashers), nil
}

func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	return strings.ReplaceAll(lower, "-", "")
}
