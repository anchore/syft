package rust

import (
	"crypto/sha256"
	"sync"
)

type outerGeneratedDepInfo struct {
	mutex sync.Mutex
	GeneratedDepInfo
}

type GeneratedDepInfo struct {
	DownloadLink string
	downloadSha  [sha256.Size]byte
	Licenses     []string
	CargoToml
}
