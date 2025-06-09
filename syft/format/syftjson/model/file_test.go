package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FileMetadataEntry_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData []byte
		assert   func(*FileMetadataEntry)
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
			assert: func(f *FileMetadataEntry) {
				assert.Equal(t, 644, f.Mode)
				assert.Equal(t, "RegularFile", f.Type)
				assert.Equal(t, 1000, f.UserID)
				assert.Equal(t, 1000, f.GroupID)
				assert.Equal(t, "text/plain", f.MIMEType)
				assert.Equal(t, int64(10174), f.Size)
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
			assert: func(f *FileMetadataEntry) {
				assert.Equal(t, 644, f.Mode)
				assert.Equal(t, "RegularFile", f.Type)
				assert.Equal(t, 1000, f.UserID)
				assert.Equal(t, 1000, f.GroupID)
				assert.Equal(t, "text/plain", f.MIMEType)
				assert.Equal(t, int64(10174), f.Size)
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
			assert: func(f *FileMetadataEntry) {
				assert.Equal(t, 0, f.Mode)
				assert.Equal(t, "RegularFile", f.Type)
				assert.Equal(t, "", f.LinkDestination)
				assert.Equal(t, 0, f.UserID)
				assert.Equal(t, 0, f.GroupID)
				assert.Equal(t, "", f.MIMEType)
				assert.Equal(t, int64(0), f.Size)
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
			assert: func(f *FileMetadataEntry) {
				assert.Equal(t, 0, f.Mode)
				assert.Equal(t, "RegularFile", f.Type)
				assert.Equal(t, "", f.LinkDestination)
				assert.Equal(t, 0, f.UserID)
				assert.Equal(t, 0, f.GroupID)
				assert.Equal(t, "", f.MIMEType)
				assert.Equal(t, int64(0), f.Size)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &FileMetadataEntry{}
			err := f.UnmarshalJSON(test.jsonData)
			require.NoError(t, err)
			test.assert(f)
		})
	}
}
