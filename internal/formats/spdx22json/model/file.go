package model

type FileType string

const (
	DocumentationFileType FileType = "DOCUMENTATION" // if the file serves as documentation
	ImageFileType         FileType = "IMAGE"         // if the file is associated with a picture image file (MIME type of image/*, e.g., .jpg, .gif)
	VideoFileType         FileType = "VIDEO"         // if the file is associated with a video file type (MIME type of video/*)
	ArchiveFileType       FileType = "ARCHIVE"       // if the file represents an archive (.tar, .jar, etc.)
	SpdxFileType          FileType = "SPDX"          // if the file is an SPDX document
	ApplicationFileType   FileType = "APPLICATION"   // if the file is associated with a specific application type (MIME type of application/*)
	SourceFileType        FileType = "SOURCE"        // if the file is human readable source code (.c, .html, etc.)
	BinaryFileType        FileType = "BINARY"        // if the file is a compiled object, target image or binary executable (.o, .a, etc.)
	TextFileType          FileType = "TEXT"          // if the file is human readable text file (MIME type of text/*)
	AudioFileType         FileType = "AUDIO"         // if the file is associated with an audio file (MIME type of audio/* , e.g. .mp3)
	OtherFileType         FileType = "OTHER"         // if the file doesn't fit into the above categories (generated artifacts, data files, etc.)
)

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
