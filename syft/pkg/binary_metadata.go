package pkg

import "github.com/anchore/syft/syft/file"

type BinaryMetadata struct {
	Matches []ClassifierMatch `mapstructure:"Matches" json:"matches"`
}

type ClassifierMatch struct {
	Classifier string        `mapstructure:"Classifier" json:"classifier"`
	Location   file.Location `mapstructure:"Location" json:"location"`
}
