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
	f.Type = string(legacy.Type)
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

type intOrStringFileType string

func (lt *intOrStringFileType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*lt = intOrStringFileType(str)
		return nil
	}

	var num int
	if err := json.Unmarshal(data, &num); err != nil {
		return fmt.Errorf("file.Type must be either string or int, got: %s", string(data))
	}

	var fileType stereoFile.Type
	switch num {
	case 0:
		fileType = stereoFile.TypeRegular
	case 1:
		fileType = stereoFile.TypeHardLink
	case 2:
		fileType = stereoFile.TypeSymLink
	case 3:
		fileType = stereoFile.TypeCharacterDevice
	case 4:
		fileType = stereoFile.TypeBlockDevice
	case 5:
		fileType = stereoFile.TypeDirectory
	case 6:
		fileType = stereoFile.TypeFIFO
	case 7:
		fileType = stereoFile.TypeSocket
	default:
		fileType = stereoFile.TypeIrregular
	}

	*lt = intOrStringFileType(fileType.String())
	return nil
}

func convertFileModeToBase8(rawMode int) int {
	octalStr := fmt.Sprintf("%o", rawMode)
	// we don't need to check that this is a valid octal string since the input is always an integer
	result, _ := strconv.Atoi(octalStr)
	return result
}
