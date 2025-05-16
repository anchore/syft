package pkg

import "github.com/anchore/syft/syft/file"

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

// PEBinary represents metadata captured from a Portable Executable formatted binary (dll, exe, etc.)
type PEBinary struct {
	VersionResources KeyValues
}
