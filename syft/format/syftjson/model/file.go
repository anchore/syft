package model

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

type File struct {
	ID         string             `json:"id"`
	Location   file.Coordinates   `json:"location"`
	Metadata   *FileMetadataEntry `json:"metadata,omitempty"`
	Contents   string             `json:"contents,omitempty"`
	Digests    []file.Digest      `json:"digests,omitempty"`
	Licenses   []FileLicense      `json:"licenses,omitempty"`
	Executable *file.Executable   `json:"executable,omitempty"`
	Unknowns   []string           `json:"unknowns,omitempty"`
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

type FileLicense struct {
	Value          string               `json:"value"`
	SPDXExpression string               `json:"spdxExpression"`
	Type           license.Type         `json:"type"`
	Evidence       *FileLicenseEvidence `json:"evidence,omitempty"`
}

type FileLicenseEvidence struct {
	Confidence int `json:"confidence"`
	Offset     int `json:"offset"`
	Extent     int `json:"extent"`
}
