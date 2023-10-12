package pkg

// StaticBinaryPackageMetadata Represents metadata captured from the .note.package section of the binary
type StaticBinaryPackageMetadata struct {
	Type    string   `json:"type"`
	Vendor  string   `json:"vendor"`
	System  string   `json:"system"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Source  string   `json:"sourceRepo"`
	Commit  string   `json:"commit"`
	PURL    string   `json:"purl"`
	CPE     string   `json:"cpe"`
	Deps    []string ``
}

// StaticBinaryLibraryMetadata Represents metadata captured from the .note.package section of the included imported library files of a static binary
type StaticBinaryLibraryMetadata struct {
	Type    string `json:"type"`
	Vendor  string `json:"vendor"`
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"sourceRepo"`
	Commit  string `json:"commit"`
	PURL    string `json:"purl"`
	CPE     string `json:"cpe"`
	Parent  string ``
}
