package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FileMetadataEntry_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData []byte
		expected FileMetadataEntry
	}{
		{
			name: "unmarshal current format",
			jsonData: []byte(`{
             "mode": 644,
             "type": "RegularFile",
             "linkDestination": "/usr/bin/python3",
             "userID": 1000,
             "groupID": 1000,
             "mimeType": "text/plain",
             "size": 10174
          }`),
			expected: FileMetadataEntry{
				Mode:            644,
				Type:            "RegularFile",
				LinkDestination: "/usr/bin/python3",
				UserID:          1000,
				GroupID:         1000,
				MIMEType:        "text/plain",
				Size:            10174,
			},
		},
		{
			name: "unmarshal legacy sbom import format",
			jsonData: []byte(`{
             "Mode": 644,
             "Type": "RegularFile",
             "LinkDestination": "/usr/bin/python3",
             "UserID": 1000,
             "GroupID": 1000,
             "MIMEType": "text/plain",
             "Size": 10174
          }`),
			expected: FileMetadataEntry{
				Mode:            644,
				Type:            "RegularFile",
				LinkDestination: "/usr/bin/python3",
				UserID:          1000,
				GroupID:         1000,
				MIMEType:        "text/plain",
				Size:            10174,
			},
		},
		{
			name: "unmarshal legacy sbom import format - integer type",
			jsonData: []byte(`{
             "Mode": 644,
             "Type": 0,
             "LinkDestination": "/usr/bin/python3",
             "UserID": 1000,
             "GroupID": 1000,
             "MIMEType": "text/plain",
             "Size": 10174
          }`),
			expected: FileMetadataEntry{
				Mode:            644,
				Type:            "RegularFile",
				LinkDestination: "/usr/bin/python3",
				UserID:          1000,
				GroupID:         1000,
				MIMEType:        "text/plain",
				Size:            10174,
			},
		},
		{
			name: "unmarshal minimal current format",
			jsonData: []byte(`{
             "mode": 0,
             "type": "RegularFile",
             "userID": 0,
             "groupID": 0,
             "size": 0
          }`),
			expected: FileMetadataEntry{
				Type: "RegularFile",
			},
		},
		{
			name: "unmarshal minimal legacy format",
			jsonData: []byte(`{
             "Mode": 0,
             "Type": "RegularFile",
             "UserID": 0,
             "GroupID": 0,
             "Size": 0
          }`),
			expected: FileMetadataEntry{
				Type: "RegularFile",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual FileMetadataEntry
			err := actual.UnmarshalJSON(test.jsonData)
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("FileMetadataEntry mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}

func Test_intOrStringFileType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData []byte
		expected string
		wantErr  require.ErrorAssertionFunc
	}{
		// string inputs - should pass through unchanged
		{
			name:     "string RegularFile",
			jsonData: []byte(`"RegularFile"`),
			expected: "RegularFile",
		},
		{
			name:     "string HardLink",
			jsonData: []byte(`"HardLink"`),
			expected: "HardLink",
		},
		{
			name:     "string Directory",
			jsonData: []byte(`"Directory"`),
			expected: "Directory",
		},
		{
			name:     "string custom value",
			jsonData: []byte(`"CustomFileType"`),
			expected: "CustomFileType",
		},
		// integer inputs - should convert to string representation
		{
			name:     "int 0 (TypeRegular)",
			jsonData: []byte(`0`),
			expected: "RegularFile",
		},
		{
			name:     "int 1 (TypeHardLink)",
			jsonData: []byte(`1`),
			expected: "HardLink",
		},
		{
			name:     "int 2 (TypeSymLink)",
			jsonData: []byte(`2`),
			expected: "SymbolicLink",
		},
		{
			name:     "int 3 (TypeCharacterDevice)",
			jsonData: []byte(`3`),
			expected: "CharacterDevice",
		},
		{
			name:     "int 4 (TypeBlockDevice)",
			jsonData: []byte(`4`),
			expected: "BlockDevice",
		},
		{
			name:     "int 5 (TypeDirectory)",
			jsonData: []byte(`5`),
			expected: "Directory",
		},
		{
			name:     "int 6 (TypeFIFO)",
			jsonData: []byte(`6`),
			expected: "FIFONode",
		},
		{
			name:     "int 7 (TypeSocket)",
			jsonData: []byte(`7`),
			expected: "Socket",
		},
		{
			name:     "int 8 (TypeIrregular)",
			jsonData: []byte(`8`),
			expected: "IrregularFile",
		},
		{
			name:     "unknown int",
			jsonData: []byte(`99`),
			expected: "Unknown",
		},
		{
			name:     "negative int",
			jsonData: []byte(`-1`),
			expected: "Unknown",
		},
		{
			name:     "null value",
			jsonData: []byte(`null`),
		},
		{
			name:     "invalid JSON",
			jsonData: []byte(`{`),
			wantErr:  require.Error,
		},
		{
			name:     "boolean value",
			jsonData: []byte(`true`),
			wantErr:  require.Error,
		},
		{
			name:     "array value",
			jsonData: []byte(`[]`),
			wantErr:  require.Error,
		},
		{
			name:     "object value",
			jsonData: []byte(`{}`),
			wantErr:  require.Error,
		},
		{
			name:     "float value",
			jsonData: []byte(`1.5`),
			wantErr:  require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			var ft intOrStringFileType
			err := ft.UnmarshalJSON(test.jsonData)
			test.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, test.expected, string(ft))
		})
	}
}

func Test_convertFileModeToBase8(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			name:     "no permissions",
			input:    0,
			expected: 0,
		},
		{
			name:     "symlink + rwxrwxrwx",
			input:    134218239,
			expected: 1000000777,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := convertFileModeToBase8(tt.input)

			require.Equal(t, tt.expected, actual)
		})
	}
}
