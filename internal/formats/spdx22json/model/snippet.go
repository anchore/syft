package model

type StartPointer struct {
	Offset     int `json:"offset,omitempty"`
	LineNumber int `json:"lineNumber,omitempty"`
	// SPDX ID for File
	Reference string `json:"reference"`
}

type EndPointer struct {
	Offset     int `json:"offset,omitempty"`
	LineNumber int `json:"lineNumber,omitempty"`
	// SPDX ID for File
	Reference string `json:"reference"`
}

type Range struct {
	StartPointer StartPointer `json:"startPointer"`
	EndPointer   EndPointer   `json:"endPointer"`
}

type Snippet struct {
	Item
	// Licensing information that was discovered directly in the subject snippet. This is also considered a declared
	// license for the snippet. (elements are license expressions)
	LicenseInfoInSnippets []string `json:"licenseInfoInSnippets"`
	// SPDX ID for File. File containing the SPDX element (e.g. the file contaning a snippet).
	SnippetFromFile string `json:"snippetFromFile"`
	// (At least 1 range is required). This field defines the byte range in the original host file (in X.2) that the
	// snippet information applies to.
	Ranges []Range `json:"ranges"`
}
