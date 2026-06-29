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

// Pre-computed hash values for empty files
const (
	emptyMD5    = "d41d8cd98f00b204e9800998ecf8427e"
	emptySHA1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	emptySHA224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	emptySHA384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	emptySHA512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

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

	// For empty files, use pre-computed constants for better performance
	if size == 0 {
		result := make([]file.Digest, len(hashes))
		for idx, hashObj := range hashes {
			var value string
			switch hashObj {
			case crypto.MD5:
				value = emptyMD5
			case crypto.SHA1:
				value = emptySHA1
			case crypto.SHA224:
				value = emptySHA224
			case crypto.SHA256:
				value = emptySHA256
			case crypto.SHA384:
				value = emptySHA384
			case crypto.SHA512:
				value = emptySHA512
			default:
				// Fallback to calculated hash for unsupported algorithms
				value = fmt.Sprintf("%+x", hashers[idx].Sum(nil))
			}
			result[idx] = file.Digest{
				Algorithm: CleanDigestAlgorithmName(hashObj.String()),
				Value:     value,
			}
		}
		return result, nil
	}

	result := make([]file.Digest, len(hashes))
	// Capture digests for all files with content. It is important to base this on actual
	// content SIZE rather than FILE TYPE, as it is possible for a tar to be crafted with
	// a header-only file type but a body is still allowed.
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
