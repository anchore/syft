package source

import "github.com/anchore/syft/syft/file"

type SnapMetadata struct {
	// Summary is a brief description of the snap package
	Summary string `yaml:"summary" json:"summary,omitempty"`

	// Base is the base snap this package builds upon
	Base string `yaml:"base" json:"base,omitempty"`

	// Grade is the development stage (stable, candidate, beta, edge)
	Grade string `yaml:"grade" json:"grade,omitempty"`

	// Confinement is the security isolation level (strict, classic, devmode)
	Confinement string `yaml:"confinement" json:"confinement,omitempty"`

	// Architectures are the supported CPU architectures
	Architectures []string `yaml:"architectures" json:"architectures,omitempty"`

	// Digests are hashes of the snap squashfs files
	Digests []file.Digest `yaml:"digests" json:"digests,omitempty"`
}
