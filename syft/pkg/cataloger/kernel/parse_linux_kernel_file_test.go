package kernel

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// minimalKernelELF builds an ELF64 with a .shstrtab and a .rodata section that
// holds the given payload. It is enough for debug/elf to parse and for the
// kernel banner lookup to read .rodata.
func minimalKernelELF(machine uint16, rodata string) []byte {
	shstrtab := []byte("\x00.shstrtab\x00.rodata\x00")
	shoff := 64 + len(shstrtab) + len(rodata)
	shoff = (shoff + 7) &^ 7
	buf := make([]byte, shoff+3*64)

	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(buf[16:], 2)       // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], machine) // e_machine
	binary.LittleEndian.PutUint32(buf[20:], 1)       // e_version
	binary.LittleEndian.PutUint64(buf[40:], uint64(shoff))
	binary.LittleEndian.PutUint16(buf[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[58:], 64) // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:], 3)  // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 1)  // e_shstrndx

	copy(buf[64:], shstrtab)
	copy(buf[64+len(shstrtab):], rodata)

	sh := func(index int, name, typ uint32, offset, size uint64) {
		base := shoff + index*64
		binary.LittleEndian.PutUint32(buf[base:], name)
		binary.LittleEndian.PutUint32(buf[base+4:], typ)
		binary.LittleEndian.PutUint64(buf[base+24:], offset)
		binary.LittleEndian.PutUint64(buf[base+32:], size)
		binary.LittleEndian.PutUint64(buf[base+48:], 1)
	}
	sh(1, 1, 3, 64, uint64(len(shstrtab)))                      // .shstrtab, SHT_STRTAB
	sh(2, 11, 1, uint64(64+len(shstrtab)), uint64(len(rodata))) // .rodata, SHT_PROGBITS

	return buf
}

func TestParseELFLinuxKernel_vmlinux(t *testing.T) {
	banner := "6.1.0-test (build@host) #1 SMP PREEMPT_DYNAMIC Fri Jan 1 00:00:00 UTC 2026"
	data := minimalKernelELF(62 /* EM_X86_64 */, "junk "+linuxVersionBanner+banner+"\nrest")

	got, ok := parseELFLinuxKernel(bytes.NewReader(data))

	assert.True(t, ok)
	assert.Equal(t, "x86", got.Architecture)
	assert.Equal(t, "vmlinux", got.Format)
	assert.Equal(t, "6.1.0-test", got.Version)
	assert.Equal(t, banner, got.ExtendedVersion)
}

func TestParseELFLinuxKernel_arm64(t *testing.T) {
	data := minimalKernelELF(183 /* EM_AARCH64 */, linuxVersionBanner+"6.6.1 (build@host) #1 SMP\n")

	got, ok := parseELFLinuxKernel(bytes.NewReader(data))

	assert.True(t, ok)
	assert.Equal(t, "arm64", got.Architecture)
	assert.Equal(t, "6.6.1", got.Version)
}

func TestParseELFLinuxKernel_NoBanner(t *testing.T) {
	data := minimalKernelELF(62, "an ordinary ELF payload")

	_, ok := parseELFLinuxKernel(bytes.NewReader(data))

	assert.False(t, ok)
}

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
