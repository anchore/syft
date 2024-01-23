package options

import (
	"testing"
)

func TestFormatCyclonedxXML_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := FormatCyclonedxXML{}
	ftp := setAllToNonZero(t, &ft).(*FormatCyclonedxXML)

	subject := ftp.config("Version")
	assertExpectedValue(t, subject)
}
