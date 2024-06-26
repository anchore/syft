package rust

import (
	"crypto/sha1" //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
	"crypto/sha256"
)

type RegistryGeneratedInfo struct {
	IsLocalFile bool
	RepositoryConfig
}

func EmptyRegistryGeneratedDepInfo() RegistryGeneratedInfo {
	return RegistryGeneratedInfo{
		RepositoryConfig: emptyRepositoryConfig(),
	}
}

type SourceGeneratedDepInfo struct {
	DownloadLink string
	DownloadSha  [sha256.Size]byte
	Licenses     []string
	CargoToml
	PathSha1Hashes map[string][sha1.Size]byte //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
}

func EmptySourceGeneratedDepInfo() SourceGeneratedDepInfo {
	return SourceGeneratedDepInfo{}
}
