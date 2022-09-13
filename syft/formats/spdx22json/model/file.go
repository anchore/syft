package model

type File struct {
	Item
	// (At least one is required.) The checksum property provides a mechanism that can be used to verify that the
	// contents of a File or Package have not changed.
	Checksums []Checksum `json:"checksums,omitempty"`
	// This field provides a place for the SPDX file creator to record file contributors. Contributors could include
	// names of copyright holders and/or authors who may not be copyright holders yet contributed to the file content.
	FileContributors []string `json:"fileContributors,omitempty"`
	// Each element is a SPDX ID for a File.
	FileDependencies []string `json:"fileDependencies,omitempty"`
	// The name of the file relative to the root of the package.
	FileName string `json:"fileName"`
	// The type of the file
	FileTypes []string `json:"fileTypes,omitempty"`
	// This field provides a place for the SPDX file creator to record potential legal notices found in the file.
	// This may or may not include copyright statements.
	NoticeText string `json:"noticeText,omitempty"`
	// Indicates the project in which the SpdxElement originated. Tools must preserve doap:homepage and doap:name
	// properties and the URI (if one is known) of doap:Project resources that are values of this property. All other
	// properties of doap:Projects are not directly supported by SPDX and may be dropped when translating to or
	// from some SPDX formats (deprecated).
	ArtifactOf []string `json:"artifactOf,omitempty"`
}
