package model

import (
	"encoding/json"
	"fmt"
	"strconv"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
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

type auxFileMetadataEntry FileMetadataEntry
type fileMetadataEntryWithLegacyHint struct {
	*auxFileMetadataEntry `json:",inline"`
	LegacyHint            any `json:"FileInfo"`
}

func (f *FileMetadataEntry) UnmarshalJSON(data []byte) error {
	aux := fileMetadataEntryWithLegacyHint{
		auxFileMetadataEntry: (*auxFileMetadataEntry)(f),
	}
	if err := json.Unmarshal(data, &aux); err == nil {
		fieldsSpecified := f.Mode != 0 || f.Type != "" || f.LinkDestination != "" ||
			f.UserID != 0 || f.GroupID != 0 || f.MIMEType != "" || f.Size != 0
		if aux.LegacyHint == nil && fieldsSpecified {
			// we should have at least one field set to a non-zero value... (this is not a legacy shape)
			return nil
		}
	}

	var legacy sbomImportLegacyFileMetadataEntry
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	if !legacy.Type.WasInt {
		// this occurs for document shapes from a non-import path and indicates that the mode has already been converted to octal.
		// That being said, we want to handle all legacy shapes the same, so we will convert this to base 10 for consistency.
		legacy.Mode = convertBase8ToBase10(legacy.Mode)
	}

	f.Mode = legacy.Mode
	f.Type = legacy.Type.Value
	f.LinkDestination = legacy.LinkDestination
	f.UserID = legacy.UserID
	f.GroupID = legacy.GroupID
	f.MIMEType = legacy.MIMEType
	f.Size = legacy.Size

	return nil
}

type sbomImportLegacyFileMetadataEntry struct {
	Mode            int                 `json:"Mode"`
	Type            intOrStringFileType `json:"Type"`
	LinkDestination string              `json:"LinkDestination"`
	UserID          int                 `json:"UserID"`
	GroupID         int                 `json:"GroupID"`
	MIMEType        string              `json:"MIMEType"`
	Size            int64               `json:"Size"`
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

type intOrStringFileType struct {
	Value  string
	WasInt bool
}

func (lt *intOrStringFileType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		lt.Value = str
		return nil
	}

	var num stereoFile.Type
	if err := json.Unmarshal(data, &num); err != nil {
		return fmt.Errorf("file.Type must be either string or int, got: %s", string(data))
	}

	lt.Value = num.String()
	lt.WasInt = true
	return nil
}

func convertBase10ToBase8(rawMode int) int {
	octalStr := fmt.Sprintf("%o", rawMode)
	// we don't need to check that this is a valid octal string since the input is always an integer
	result, _ := strconv.Atoi(octalStr)
	return result
}

func convertBase8ToBase10(octalMode int) int {
	octalStr := strconv.Itoa(octalMode)
	result, _ := strconv.ParseInt(octalStr, 8, 64)

	return int(result)
}
