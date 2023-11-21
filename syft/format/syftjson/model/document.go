package model

// Document represents the syft cataloging findings as a JSON document
type Document struct {
	Schema        Schema         `json:"schema"`          // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
	Descriptor    Descriptor     `json:"descriptor"`      // Descriptor is a block containing self-describing information about syft
	Source        Source         `json:"source"`          // Source represents the original object that was cataloged
	Distro        LinuxRelease   `json:"distro"`          // Distro represents the Linux distribution that was detected from the source
	Packages      []Package      `json:"packages"`        // Packages is the list of packages discovered
	Relationships []Relationship `json:"relationships"`   // Relationships is a list of package-to-package, package-to-file, and file-to-package relationships
	Files         []File         `json:"files,omitempty"` // Files is a list of all files at their real path and any associated metadata about that file
}

// Descriptor describes what created the document as well as surrounding metadata
type Descriptor struct {
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	Configuration interface{} `json:"configuration,omitempty"`
}

type Schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}
