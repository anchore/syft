package options

import (
	"testing"
)

func TestFormatSyftJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := &FormatSyftJSON{}
	ft = setAllToNonZero(t, ft).(*FormatSyftJSON)

	subject := ft.config()
	assertExpectedValue(t, subject)
}
