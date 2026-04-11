package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLinuxKernelMetadata_bzImage_PositiveCase(t *testing.T) {
	magicType := []string{
		"Linux kernel",
		"x86 boot executable",
		"bzImage",
		"version 4.12.29-17011406-standard (oe-user@oe-host) #1 SMP Tue Apr 20 22:18:27 UTC 2021",
	}

	got := parseLinuxKernelMetadata(magicType)

	assert.Equal(t, "x86", got.Architecture)
	assert.Equal(t, "bzImage", got.Format)
	assert.Equal(t, "4.12.29-17011406-standard", got.Version)
	assert.NotEmpty(t, got.ExtendedVersion)
}

func TestParseLinuxKernelMetadata_bzImage_EmptyVersion(t *testing.T) {
	magicType := []string{
		"Linux kernel",
		"x86 boot executable",
		"bzImage",
		// no "version ..." token
	}

	got := parseLinuxKernelMetadata(magicType)

	assert.Equal(t, "bzImage", got.Format)
	assert.Empty(t, got.Version, "version should be empty when no version token is present")
}
