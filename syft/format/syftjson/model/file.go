package model

import (
	"encoding/json"

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

func (f *FileMetadataEntry) UnmarshalJSON(data []byte) error {
	type Alias FileMetadataEntry
	aux := (*Alias)(f)

	if err := json.Unmarshal(data, aux); err == nil {
		// we should have at least one field set to a non-zero value... otherwise this is a legacy entry
		if f.Mode != 0 || f.Type != "" || f.LinkDestination != "" ||
			f.UserID != 0 || f.GroupID != 0 || f.MIMEType != "" || f.Size != 0 {
			return nil
		}
	}

	var legacy sbomImportLegacyFileMetadataEntry
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	f.Mode = legacy.Mode
	f.Type = legacy.Type
	f.LinkDestination = legacy.LinkDestination
	f.UserID = legacy.UserID
	f.GroupID = legacy.GroupID
	f.MIMEType = legacy.MIMEType
	f.Size = legacy.Size

	return nil
}

type sbomImportLegacyFileMetadataEntry struct {
	Mode            int    `json:"Mode"`
	Type            string `json:"Type"`
	LinkDestination string `json:"LinkDestination"`
	UserID          int    `json:"UserID"`
	GroupID         int    `json:"GroupID"`
	MIMEType        string `json:"MIMEType"`
	Size            int64  `json:"Size"`
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
