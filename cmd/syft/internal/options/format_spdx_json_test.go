package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatSPDXJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := &FormatSPDXJSON{}
	ft = setAllToNonZero(t, ft).(*FormatSPDXJSON)

	subject := ft.config("Version")
	require.Equal(t, "Version", subject.Version)
	require.Equal(t, "2.3", subject.DefaultVersion)
	require.True(t, subject.Pretty)
}
