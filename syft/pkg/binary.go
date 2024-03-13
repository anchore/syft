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
	Type       string `json:"type,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	System     string `json:"system,omitempty"`
	SourceRepo string `json:"sourceRepo,omitempty"`
	Commit     string `json:"commit,omitempty"`
}
