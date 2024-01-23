package options

import (
	"testing"
)

func TestFormatSPDXJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := &FormatSPDXJSON{}
	ft = setAllToNonZero(t, ft).(*FormatSPDXJSON)

	subject := ft.buildConfig("Version")
	assertExpectedValue(t, subject)
}
