package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertAbsoluteToRelative(t *testing.T) {
	tests := []struct {
		name    string
		absPath string
		want    string
	}{
		{
			name:    "absolute path",
			absPath: "/usr/bin/foo",
			want:    "usr/bin/foo",
		},
		{
			name:    "relative path",
			absPath: "relative/path/bar",
			want:    "relative/path/bar",
		},
		{
			name:    "root path",
			absPath: "/",
			want:    "",
		},
		{
			name:    "dot relative path",
			absPath: "./foo",
			want:    "./foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertAbsoluteToRelative(tt.absPath)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
