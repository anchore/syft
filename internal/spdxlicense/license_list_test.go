package spdxlicense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLicenceListIDs(t *testing.T) {
	// do a sanity check on the generated data
	assert.Equal(t, "0BSD", licenseIDs["0bsd"])
	assert.Equal(t, "ZPL-2.1", licenseIDs["zpl-2.1"])
	assert.Equal(t, "GPL-2.0", licenseIDs["gpl-2"])
	assert.NotEmpty(t, Version)
}
