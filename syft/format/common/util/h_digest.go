package util

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// HDigestToSHA converts a h# digest, such as h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU= to an
// algorithm such as sha256 and a hex encoded digest
func HDigestToSHA(digest string) (string, string, error) {
	// hash is base64, but we need hex encode
	parts := strings.Split(digest, ":")
	if len(parts) == 2 {
		algo := parts[0]
		hash := parts[1]
		checksum, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return "", "", err
		}

		hexStr := hex.EncodeToString(checksum)

		switch algo {
		// golang h1 hash == sha256
		case "h1":
			algo = "sha256"
		default:
			return "", "", fmt.Errorf("unsupported h#digest algorithm: %s", algo)
		}

		return algo, hexStr, nil
	}

	return "", "", fmt.Errorf("invalid h#digest: %s", digest)
}

// HDigestFromSHA converts an algorithm, such sha256 with a hex encoded digest to a
// h# value such as h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
func HDigestFromSHA(algorithm string, digest string) (string, error) {
	if digest == "" {
		return "", fmt.Errorf("no digest value provided")
	}
	// digest is hex, but we need to base64 encode
	algorithm = strings.ToLower(algorithm)
	if algorithm == "sha256" {
		checksum, err := hex.DecodeString(digest)
		if err != nil {
			return "", err
		}
		// hash is hex, but we need base64
		b64digest := base64.StdEncoding.EncodeToString(checksum)
		return fmt.Sprintf("h1:%s", b64digest), nil
	}
	return "", fmt.Errorf("not a recognized h#digest algorithm: %s", algorithm)
}
