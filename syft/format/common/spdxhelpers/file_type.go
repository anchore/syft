package spdxhelpers

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
