package options

import (
	"testing"
)

func TestFormatSPDXJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := FormatSPDXJSON{}
	ftp := setAllToNonZero(t, &ft).(*FormatSPDXJSON)

	subject := ftp.buildConfig("1.2")
	assertNoZeroFields(t, subject)
}
