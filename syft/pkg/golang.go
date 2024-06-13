package pkg

import "github.com/anchore/syft/syft/sort"

// GolangBinaryBuildinfoEntry represents all captured data for a Golang binary
type GolangBinaryBuildinfoEntry struct {
	BuildSettings     KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string    `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string    `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string    `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string    `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string  `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`
	GoExperiments     []string  `json:"goExperiments,omitempty" cyclonedx:"goExperiments"`
}

// GolangModuleEntry represents all captured data for a Golang source scan with go.mod/go.sum
type GolangModuleEntry struct {
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
}

func (m GolangModuleEntry) Compare(other GolangModuleEntry) int {
	return sort.CompareOrd(m.H1Digest, other.H1Digest)
}
func (m GolangBinaryBuildinfoEntry) Compare(other GolangBinaryBuildinfoEntry) int {
	if i := sort.Compare(m.BuildSettings, other.BuildSettings); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.GoCompiledVersion, other.GoCompiledVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Architecture, other.Architecture); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.H1Digest, other.H1Digest); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.MainModule, other.MainModule); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.GoCryptoSettings, other.GoCryptoSettings); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.GoExperiments, other.GoExperiments); i != 0 {
		return i
	}
	return 0
}
func (m GolangModuleEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(GolangModuleEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m GolangBinaryBuildinfoEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(GolangBinaryBuildinfoEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
