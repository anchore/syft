package kernel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// minimalKOBytes constructs a minimal ELF64 LE relocatable object with a .modinfo
// section containing the given null-terminated key=value entries.
func minimalKOBytes(entries []string) []byte {
	// Build .modinfo section data: each entry is key=value\0
	var modinfo []byte
	for _, e := range entries {
		modinfo = append(modinfo, []byte(e)...)
		modinfo = append(modinfo, 0)
	}

	// Section name string table: \0 .modinfo\0 .shstrtab\0
	shstrtab := []byte("\x00.modinfo\x00.shstrtab\x00")
	modinfoNameOff := uint32(1)  // offset of ".modinfo" in shstrtab
	shstrtabNameOff := uint32(10) // offset of ".shstrtab" in shstrtab

	// ELF64 header is 64 bytes.
	// We have 3 sections: null, .modinfo, .shstrtab
	const (
		elfHeaderSize  = 64
		sectionHdrSize = 64
		numSections    = 3
	)

	modinfoOff := uint64(elfHeaderSize)
	modinfoSize := uint64(len(modinfo))

	shstrtabOff := modinfoOff + modinfoSize
	shstrtabSize := uint64(len(shstrtab))

	// Align section header table to 8 bytes
	shdrsOff := shstrtabOff + shstrtabSize
	if shdrsOff%8 != 0 {
		shdrsOff += 8 - (shdrsOff % 8)
	}

	buf := new(bytes.Buffer)
	le := binary.LittleEndian

	// ELF header
	buf.Write([]byte{0x7f, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                         // EI_CLASS: ELFCLASS64
	buf.WriteByte(1)                         // EI_DATA: ELFDATA2LSB
	buf.WriteByte(1)                         // EI_VERSION: EV_CURRENT
	buf.WriteByte(0)                         // EI_OSABI
	buf.Write(make([]byte, 8))               // EI_ABIVERSION + padding

	writeU16 := func(v uint16) { binary.Write(buf, le, v) } //nolint:errcheck
	writeU32 := func(v uint32) { binary.Write(buf, le, v) } //nolint:errcheck
	writeU64 := func(v uint64) { binary.Write(buf, le, v) } //nolint:errcheck

	writeU16(1)               // e_type: ET_REL
	writeU16(62)              // e_machine: EM_X86_64
	writeU32(1)               // e_version: EV_CURRENT
	writeU64(0)               // e_entry
	writeU64(0)               // e_phoff (no program headers)
	writeU64(shdrsOff)        // e_shoff
	writeU32(0)               // e_flags
	writeU16(elfHeaderSize)   // e_ehsize
	writeU16(0)               // e_phentsize
	writeU16(0)               // e_phnum
	writeU16(sectionHdrSize)  // e_shentsize
	writeU16(numSections)     // e_shnum
	writeU16(numSections - 1) // e_shstrndx (.shstrtab is last)

	// Write section data
	buf.Write(modinfo)
	buf.Write(shstrtab)

	// Pad to shdrsOff
	for uint64(buf.Len()) < shdrsOff {
		buf.WriteByte(0)
	}

	// Section header 0: null
	buf.Write(make([]byte, sectionHdrSize))

	// Section header 1: .modinfo  (SHT_PROGBITS=1)
	writeU32(modinfoNameOff) // sh_name
	writeU32(1)              // sh_type: SHT_PROGBITS
	writeU64(0)              // sh_flags
	writeU64(0)              // sh_addr
	writeU64(modinfoOff)     // sh_offset
	writeU64(modinfoSize)    // sh_size
	writeU32(0)              // sh_link
	writeU32(0)              // sh_info
	writeU64(1)              // sh_addralign
	writeU64(0)              // sh_entsize

	// Section header 2: .shstrtab (SHT_STRTAB=3)
	writeU32(shstrtabNameOff) // sh_name
	writeU32(3)               // sh_type: SHT_STRTAB
	writeU64(0)               // sh_flags
	writeU64(0)               // sh_addr
	writeU64(shstrtabOff)     // sh_offset
	writeU64(shstrtabSize)    // sh_size
	writeU32(0)               // sh_link
	writeU32(0)               // sh_info
	writeU64(1)               // sh_addralign
	writeU64(0)               // sh_entsize

	return buf.Bytes()
}

func gzCompress(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func xzCompress(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := xz.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func zstCompress(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// makeLocationReadCloser wraps a byte slice as a file.LocationReadCloser with the given path.
func makeLocationReadCloser(path string, data []byte) file.LocationReadCloser {
	return file.LocationReadCloser{
		Location:   file.NewVirtualLocation(path, path),
		ReadCloser: io.NopCloser(bytes.NewReader(data)),
	}
}

func TestParseLinuxKernelModuleFile_Compressed(t *testing.T) {
	modinfo := []string{
		"name=dummy_mod",
		"version=1.2.3",
		"vermagic=6.1.0-rc1 SMP mod_unload",
		"license=GPL v2",
	}
	koBytes := minimalKOBytes(modinfo)

	tests := []struct {
		name     string
		path     string
		data     []byte
		wantName string
		wantVer  string
		wantKV   string // expected KernelVersion from vermagic
	}{
		{
			name:     "uncompressed .ko",
			path:     "/lib/modules/6.1.0-rc1/kernel/dummy_mod.ko",
			data:     koBytes,
			wantName: "dummy_mod",
			wantVer:  "1.2.3",
			wantKV:   "6.1.0-rc1",
		},
		{
			name:     "gzip-compressed .ko.gz",
			path:     "/lib/modules/6.1.0-rc1/kernel/dummy_mod.ko.gz",
			data:     gzCompress(koBytes),
			wantName: "dummy_mod",
			wantVer:  "1.2.3",
			wantKV:   "6.1.0-rc1",
		},
		{
			name:     "xz-compressed .ko.xz",
			path:     "/lib/modules/6.1.0-rc1/kernel/dummy_mod.ko.xz",
			data:     xzCompress(koBytes),
			wantName: "dummy_mod",
			wantVer:  "1.2.3",
			wantKV:   "6.1.0-rc1",
		},
		{
			name:     "zstd-compressed .ko.zst",
			path:     "/lib/modules/6.1.0-rc1/kernel/dummy_mod.ko.zst",
			data:     zstCompress(koBytes),
			wantName: "dummy_mod",
			wantVer:  "1.2.3",
			wantKV:   "6.1.0-rc1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := makeLocationReadCloser(tt.path, tt.data)
			pkgs, rels, err := parseLinuxKernelModuleFile(context.Background(), nil, &generic.Environment{}, reader)
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Empty(t, rels)
			assert.Equal(t, tt.wantName, pkgs[0].Name)
			assert.Equal(t, tt.wantVer, pkgs[0].Version)

			meta, ok := pkgs[0].Metadata.(pkg.LinuxKernelModule)
			require.True(t, ok)
			assert.Equal(t, tt.wantKV, meta.KernelVersion)
		})
	}
}

func TestDecompressedModuleReader(t *testing.T) {
	koBytes := minimalKOBytes([]string{"name=test", "vermagic=5.15.0 SMP mod_unload"})

	tests := []struct {
		name string
		path string
		data []byte
	}{
		{"uncompressed", "/lib/modules/5.15.0/kernel/test.ko", koBytes},
		{"gz", "/lib/modules/5.15.0/kernel/test.ko.gz", gzCompress(koBytes)},
		{"xz", "/lib/modules/5.15.0/kernel/test.ko.xz", xzCompress(koBytes)},
		{"zst", "/lib/modules/5.15.0/kernel/test.ko.zst", zstCompress(koBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := struct {
				io.ReadCloser
				io.ReaderAt
				io.Seeker
			}{
				ReadCloser: io.NopCloser(bytes.NewReader(tt.data)),
				ReaderAt:   bytes.NewReader(tt.data),
				Seeker:     bytes.NewReader(tt.data),
			}
			got, err := decompressedModuleReader(tt.path, wrapped)
			require.NoError(t, err)
			require.NotNil(t, got)

			b, err := io.ReadAll(got)
			require.NoError(t, err)
			assert.Equal(t, koBytes, b, "decompressed bytes should match original .ko bytes")
		})
	}
}
