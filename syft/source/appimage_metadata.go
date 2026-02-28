package source

import "github.com/anchore/syft/syft/file"

type AppImageMetadata struct {
	// Name is the name of the application from the .desktop file
	Name string `yaml:"name" json:"name,omitempty"`

	// Version is the version of the application from the .desktop file
	Version string `yaml:"version" json:"version,omitempty"`

	// DesktopPath is the path to the .desktop file within the .appimage
	DesktopPath string `yaml:"desktopPath" json:"desktopPath,omitempty"`

	// Digests are hashes of the .appimage file
	Digests []file.Digest `yaml:"digests" json:"digests,omitempty"`
}
