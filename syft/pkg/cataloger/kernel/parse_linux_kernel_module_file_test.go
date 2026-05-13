package kernel

import (
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	td := tmpdir.FromPath(t.TempDir())
	return tmpdir.WithValue(context.Background(), td)
}

// minimalKOBytes constructs a minimal ELF64 LE relocatable object with a .modinfo
// section containing the given null-terminated key=value entries.
func minimalKOBytes(entries []string) []byte {
	// .modinfo section: each entry is key=value\0
	var modinfo bytes.Buffer
	for _, e := range entries {
		modinfo.WriteString(e)
		modinfo.WriteByte(0)
	}

	// section header string table — embeds names of all sections back-to-back, leading null required.
	// offsets below index into this blob.
	shstrtab := []byte("\x00.modinfo\x00.shstrtab\x00")
	const (
		modinfoNameOff  uint32 = 1
		shstrtabNameOff uint32 = 10
	)

	const (
		ehdrSize    uint64 = 64
		shdrSize    uint64 = 64
		numSections uint16 = 3 // null + .modinfo + .shstrtab
	)

	// layout: [ehdr][modinfo][shstrtab][pad to 8][section headers]
	var (
		modinfoOff   = ehdrSize
		modinfoSize  = uint64(modinfo.Len())
		shstrtabOff  = modinfoOff + modinfoSize
		shstrtabSize = uint64(len(shstrtab))
		shdrsOff     = alignUp(shstrtabOff+shstrtabSize, 8)
	)

	header := elf.Header64{
		Ident: [16]byte{
			0x7f, 'E', 'L', 'F',
			byte(elf.ELFCLASS64),
			byte(elf.ELFDATA2LSB),
			byte(elf.EV_CURRENT),
		},
		Type:      uint16(elf.ET_REL),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     shdrsOff,
		Ehsize:    uint16(ehdrSize),
		Shentsize: uint16(shdrSize),
		Shnum:     numSections,
		Shstrndx:  numSections - 1, // .shstrtab is last
	}

	sections := []elf.Section64{
		{}, // SHN_UNDEF
		{
			Name:      modinfoNameOff,
			Type:      uint32(elf.SHT_PROGBITS),
			Off:       modinfoOff,
			Size:      modinfoSize,
			Addralign: 1,
		},
		{
			Name:      shstrtabNameOff,
			Type:      uint32(elf.SHT_STRTAB),
			Off:       shstrtabOff,
			Size:      shstrtabSize,
			Addralign: 1,
		},
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, header)
	buf.Write(modinfo.Bytes())
	buf.Write(shstrtab)
	for uint64(buf.Len()) < shdrsOff {
		buf.WriteByte(0)
	}
	for _, s := range sections {
		_ = binary.Write(&buf, binary.LittleEndian, s)
	}
	return buf.Bytes()
}

func alignUp(v, align uint64) uint64 {
	if v%align == 0 {
		return v
	}
	return v + (align - v%align)
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
			pkgs, rels, err := parseLinuxKernelModuleFile(testContext(t), nil, &generic.Environment{}, reader)
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
			br := bytes.NewReader(tt.data)
			wrapped := struct {
				io.ReadCloser
				io.ReaderAt
				io.Seeker
			}{
				ReadCloser: io.NopCloser(br),
				ReaderAt:   br,
				Seeker:     br,
			}
			got, err := decompressedModuleReader(testContext(t), tt.path, wrapped)
			require.NoError(t, err)
			require.NotNil(t, got)
			t.Cleanup(func() { _ = got.Close() })

			b, err := io.ReadAll(got)
			require.NoError(t, err)
			assert.Equal(t, koBytes, b, "decompressed bytes should match original .ko bytes")
		})
	}
}

func TestDecompressedModuleReader_TempFileRemovedOnClose(t *testing.T) {
	koBytes := minimalKOBytes([]string{"name=test", "vermagic=5.15.0 SMP"})
	data := gzCompress(koBytes)

	br := bytes.NewReader(data)
	wrapped := struct {
		io.ReadCloser
		io.ReaderAt
		io.Seeker
	}{
		ReadCloser: io.NopCloser(br),
		ReaderAt:   br,
		Seeker:     br,
	}

	got, err := decompressedModuleReader(testContext(t), "/test.ko.gz", wrapped)
	require.NoError(t, err)

	tfr, ok := got.(*tempFileUnionReader)
	require.True(t, ok, "expected compressed path to spill to a temp file")
	path := tfr.File.Name()

	_, err = os.Stat(path)
	require.NoError(t, err, "temp file should exist before Close")

	require.NoError(t, got.Close())

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "temp file should be removed after Close, got err=%v", err)
}
