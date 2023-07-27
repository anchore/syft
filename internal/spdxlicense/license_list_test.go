package spdxlicense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLicenceListIDs(t *testing.T) {
	// do a sanity check on the generated data
	assert.Equal(t, "0BSD", licenseIDs["0bsd"])
	assert.Equal(t, "ZPL-2.1", licenseIDs["zpl2.1"])
	assert.Equal(t, "GPL-2.0-only", licenseIDs["gpl2"])
	assert.Equal(t, "GPL-2.0-or-later", licenseIDs["gpl2+"])
	assert.Equal(t, "GFDL-1.2-or-later", licenseIDs["gfdl1.2+"])
	assert.NotEmpty(t, Version)
}
