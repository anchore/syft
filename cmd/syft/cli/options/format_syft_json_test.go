package options

import (
	"testing"
)

func TestFormatSyftJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := FormatSyftJSON{}
	ftp := setAllToNonZero(t, &ft).(*FormatSyftJSON)

	subject := ftp.buildConfig()
	assertNoZeroFields(t, subject)
}
