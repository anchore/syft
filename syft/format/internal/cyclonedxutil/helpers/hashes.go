package helpers

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

func encodeHashes(p pkg.Package) *[]cyclonedx.Hash {
	var hashes []cyclonedx.Hash
	if len(p.Digests) > 0 {
		for _, digest := range p.Digests {
			algorithm := toCycloneDXAlgorithm(digest.Algorithm)
			if algorithm != "" {
				hashes = append(hashes, cyclonedx.Hash{
					Algorithm: algorithm,
					Value:     digest.Value,
				})
			}
		}
	}
	if len(hashes) > 0 {
		return &hashes
	}
	return nil
}

// supported algorithm in cycloneDX as of 1.4
// "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
// "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3"
// syft supported digests: cmd/syft/cli/eventloop/tasks.go
// MD5, SHA1, SHA256
func toCycloneDXAlgorithm(algorithm string) cyclonedx.HashAlgorithm {
	validMap := map[string]cyclonedx.HashAlgorithm{
		"md5":        cyclonedx.HashAlgorithm("MD5"),
		"sha1":       cyclonedx.HashAlgorithm("SHA-1"),
		"sha224":     cyclonedx.HashAlgorithm("SHA-224"),
		"sha256":     cyclonedx.HashAlgorithm("SHA-256"),
		"sha384":     cyclonedx.HashAlgorithm("SHA-384"),
		"sha512":     cyclonedx.HashAlgorithm("SHA-512"),
		"sha3224":    cyclonedx.HashAlgorithm("SHA3-224"),
		"sha3256":    cyclonedx.HashAlgorithm("SHA3-256"),
		"sha3384":    cyclonedx.HashAlgorithm("SHA3-384"),
		"sha3512":    cyclonedx.HashAlgorithm("SHA3-512"),
		"blake2b256": cyclonedx.HashAlgorithm("BLAKE2b-256"),
		"blake2b384": cyclonedx.HashAlgorithm("BLAKE2b-384"),
		"blake2b512": cyclonedx.HashAlgorithm("BLAKE2b-512"),
	}

	return validMap[strings.ToLower(algorithm)]
}
