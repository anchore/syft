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

// ELFBinaryPackageNotes Represents metadata captured from the .note.package section of the binary
type ELFBinaryPackageNotes struct {
	Type   string `json:"type"`
	Vendor string `json:"vendor"`
	System string `json:"system"`
	Source string `json:"sourceRepo"`
	Commit string `json:"commit"`
}
