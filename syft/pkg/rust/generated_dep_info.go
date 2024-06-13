package rust

import (
	"crypto/sha1" //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
	"crypto/sha256"
	"sync"
)

type outerGeneratedDepInfo struct {
	mutex sync.Mutex
	GeneratedDepInfo
}

type GeneratedDepInfo struct {
	DownloadLink string
	downloadSha  [sha256.Size]byte //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
	Licenses     []string
	CargoToml
	PathSha1Hashes map[string][sha1.Size]byte
}
