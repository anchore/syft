package model

import (
	"github.com/anchore/syft/syft/file"
)

type File struct {
	ID       string             `json:"id"`
	Location file.Coordinates   `json:"location"`
	Metadata *FileMetadataEntry `json:"metadata,omitempty"`
	Contents string             `json:"contents,omitempty"`
	Digests  []file.Digest      `json:"digests,omitempty"`
}

type FileMetadataEntry struct {
	Mode            int    `json:"mode"`
	Type            string `json:"type"`
	LinkDestination string `json:"linkDestination,omitempty"`
	UserID          int    `json:"userID"`
	GroupID         int    `json:"groupID"`
	MIMEType        string `json:"mimeType"`
	Size            int64  `json:"size"`
}
