package model

import (
	"encoding/json"
	"fmt"
	"strconv"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

// File represents a file discovered during cataloging with its metadata, content digests, licenses, and relationships to packages.
type File struct {
	// ID is a unique identifier for this file within the SBOM.
	ID string `json:"id"`

	// Location is the file path and layer information where this file was found.
	Location file.Coordinates `json:"location"`

	// Metadata contains filesystem metadata such as permissions, ownership, and file type.
	Metadata *FileMetadataEntry `json:"metadata,omitempty"`

	// Contents is the file contents for small files.
	Contents string `json:"contents,omitempty"`

	// Digests contains cryptographic hashes of the file contents.
	Digests []file.Digest `json:"digests,omitempty"`

	// Licenses contains license information discovered within this file.
	Licenses []FileLicense `json:"licenses,omitempty"`

	// Executable contains executable metadata if this file is a binary.
	Executable *file.Executable `json:"executable,omitempty"`

	// Unknowns contains unknown fields for forward compatibility.
	Unknowns []string `json:"unknowns,omitempty"`
}

// FileMetadataEntry contains filesystem-level metadata attributes such as permissions, ownership, type, and size for a cataloged file.
type FileMetadataEntry struct {
	// Mode is the Unix file permission mode in octal format.
	Mode int `json:"mode"`

	// Type is the file type (e.g., "RegularFile", "Directory", "SymbolicLink").
	Type string `json:"type"`

	// LinkDestination is the target path for symbolic links.
	LinkDestination string `json:"linkDestination,omitempty"`

	// UserID is the file owner user ID.
	UserID int `json:"userID"`

	// GroupID is the file owner group ID.
	GroupID int `json:"groupID"`

	// MIMEType is the MIME type of the file contents.
	MIMEType string `json:"mimeType"`

	// Size is the file size in bytes.
	Size int64 `json:"size"`
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

// FileLicense represents license information discovered within a file's contents or metadata, including the matched license text and SPDX expression.
type FileLicense struct {
	// Value is the raw license identifier or text as found in the file.
	Value string `json:"value"`

	// SPDXExpression is the parsed SPDX license expression.
	SPDXExpression string `json:"spdxExpression"`

	// Type is the license type classification (e.g., declared, concluded, discovered).
	Type license.Type `json:"type"`

	// Evidence contains supporting evidence for this license detection.
	Evidence *FileLicenseEvidence `json:"evidence,omitempty"`
}

// FileLicenseEvidence contains supporting evidence for a license detection in a file, including the byte offset, extent, and confidence level.
type FileLicenseEvidence struct {
	// Confidence is the confidence score for this license detection (0-100).
	Confidence int `json:"confidence"`

	// Offset is the byte offset where the license text starts in the file.
	Offset int `json:"offset"`

	// Extent is the length of the license text in bytes.
	Extent int `json:"extent"`
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
