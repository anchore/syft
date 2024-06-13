package pkg

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sort"
)

// BinarySignature represents a set of matched values within a binary file.
type BinarySignature struct {
	Matches []ClassifierMatch `mapstructure:"Matches" json:"matches"`
}

// ClassifierMatch represents a single matched value within a binary file and the "class" name the search pattern represents.
type ClassifierMatch struct {
	Classifier string        `mapstructure:"Classifier" json:"classifier"`
	Location   file.Location `mapstructure:"Location" json:"location"`
}

// ELFBinaryPackageNoteJSONPayload Represents metadata captured from the .note.package section of the binary
type ELFBinaryPackageNoteJSONPayload struct {
	// these are well-known fields as defined by systemd ELF package metadata "spec" https://systemd.io/ELF_PACKAGE_METADATA/

	// Type is the type of the package (e.g. "rpm", "deb", "apk", etc.)
	Type string `json:"type,omitempty"`

	// Architecture of the binary package (e.g. "amd64", "arm", etc.)
	Architecture string `json:"architecture,omitempty"`

	// OS CPE is a CPE name for the OS, typically corresponding to CPE_NAME in os-release (e.g. cpe:/o:fedoraproject:fedora:33)
	OSCPE string `json:"osCPE,omitempty"`

	// OS is the OS name, typically corresponding to ID in os-release (e.g. "fedora")
	OS string `json:"os,omitempty"`

	// osVersion is the version of the OS, typically corresponding to VERSION_ID in os-release (e.g. "33")
	OSVersion string `json:"osVersion,omitempty"`

	// these are additional fields that are not part of the systemd spec

	// System is a context-specific name for the system that the binary package is intended to run on or a part of
	System string `json:"system,omitempty"`

	// Vendor is the individual or organization that produced the source code for the binary
	Vendor string `json:"vendor,omitempty"`

	// SourceRepo is the URL to the source repository for which the binary was built from
	SourceRepo string `json:"sourceRepo,omitempty"`

	// Commit is the commit hash of the source repository for which the binary was built from
	Commit string `json:"commit,omitempty"`
}

func (cm ClassifierMatch) Compare(other ClassifierMatch) int {
	if i := sort.CompareOrd(cm.Classifier, other.Classifier); i != 0 {
		return i
	}
	if i := sort.Compare(cm.Location, other.Location); i != 0 {
		return i
	}
	return 0
}

func (cm BinarySignature) Compare(other BinarySignature) int {
	if i := sort.CompareArrays(cm.Matches, other.Matches); i != 0 {
		return i
	}
	return 0
}
func (cm BinarySignature) TryCompare(other any) (bool, int) {
	if otherRpm, exists := other.(BinarySignature); exists {
		return true, cm.Compare(otherRpm)
	}
	return false, 0
}

func (pn ELFBinaryPackageNoteJSONPayload) Compare(other ELFBinaryPackageNoteJSONPayload) int {
	if i := sort.CompareOrd(pn.Type, other.Type); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.Architecture, other.Architecture); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.OSCPE, other.OSCPE); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.OS, other.OS); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.OSVersion, other.OSVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.System, other.System); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.Vendor, other.Vendor); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.SourceRepo, other.SourceRepo); i != 0 {
		return i
	}
	if i := sort.CompareOrd(pn.Commit, other.Commit); i != 0 {
		return i
	}
	return 0
}

func (pn ELFBinaryPackageNoteJSONPayload) TryCompare(other any) (bool, int) {
	if otherRpm, exists := other.(ELFBinaryPackageNoteJSONPayload); exists {
		return true, pn.Compare(otherRpm)
	}
	return false, 0
}
