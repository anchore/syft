package file

import (
	"crypto"
	"fmt"
	"strings"
)

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func DigestAlgorithmName(hash crypto.Hash) string {
	return CleanDigestAlgorithmName(hash.String())
}

func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	return strings.ReplaceAll(lower, "-", "")
}

func DigestHashesByName(digestAlgorithms ...string) ([]crypto.Hash, error) {
	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
		crypto.SHA512,
		crypto.BLAKE2b_256,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_512,
		crypto.RIPEMD160,
		crypto.SHA3_256,
		crypto.SHA3_512,
	} {
		supportedHashAlgorithms[DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	for _, hashStr := range digestAlgorithms {
		name := CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}
	return hashes, nil
}
