package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_Read_MultiLanguageVersionResources(t *testing.T) {
	// a localized binary carries one complete VS_VERSIONINFO block per language, and every block uses the same
	// string keys. These fixtures assert which of those blocks ends up describing the package.
	tests := []struct {
		name    string
		fixture []languageResource
		want    map[string]string
	}{
		{
			name: "prefer US English over other languages",
			// this is the shape of the binary reported in anchore/syft#5177 (Microsoft's DPInst.exe): every
			// language of the product name is present, and the resource directory sorts en-US (0x0409) ahead
			// of both pt-PT (0x0816) and es-ES (0x0c0a), so the last block read is Spanish.
			fixture: []languageResource{
				{lang: 0x0407, fields: germanFields},
				{lang: 0x0409, fields: englishFields},
				{lang: 0x0816, fields: portugueseFields},
				{lang: 0x0c0a, fields: spanishFields},
			},
			want: englishFields,
		},
		{
			name: "prefer US English regardless of directory order",
			fixture: []languageResource{
				{lang: 0x0c0a, fields: spanishFields},
				{lang: 0x0409, fields: englishFields},
			},
			want: englishFields,
		},
		{
			name: "fall back to another English variant when there is no US English",
			fixture: []languageResource{
				{lang: 0x0407, fields: germanFields},
				{lang: 0x0809, fields: britishFields}, // en-GB
				{lang: 0x0c0a, fields: spanishFields},
			},
			want: britishFields,
		},
		{
			name: "fall back to the language-neutral block when there is no English at all",
			fixture: []languageResource{
				{lang: 0x0407, fields: germanFields},
				{lang: 0x0000, fields: neutralFields},
				{lang: 0x0c0a, fields: spanishFields},
			},
			want: neutralFields,
		},
		{
			name: "fall back to the lowest language ID when there is no English or neutral block",
			fixture: []languageResource{
				{lang: 0x0c0a, fields: spanishFields},
				{lang: 0x0407, fields: germanFields},
			},
			want: germanFields,
		},
		{
			name: "a single localized block is still used",
			fixture: []languageResource{
				{lang: 0x0c0a, fields: spanishFields},
			},
			want: spanishFields,
		},
		{
			name: "never mix values from different languages",
			// the German block is missing ProductName entirely: taking it from another language would describe
			// a version resource that does not exist in the file.
			fixture: []languageResource{
				{lang: 0x0407, fields: map[string]string{"FileDescription": "Treiberpaket-Installationsprogramm", "FileVersion": "2.1"}},
				{lang: 0x0c0a, fields: spanishFields},
			},
			want: map[string]string{"FileDescription": "Treiberpaket-Installationsprogramm", "FileVersion": "2.1"},
		},
		{
			name: "string tables are matched to their declared language, not the directory entry",
			// resource compilers are free to place a table under any directory entry; the table's own szKey is
			// the more direct statement of what language its strings are written in.
			fixture: []languageResource{
				{lang: 0x0c0a, codepageKey: "040904b0", fields: englishFields},
				{lang: 0x0409, codepageKey: "0c0a04b0", fields: spanishFields},
			},
			want: englishFields,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Read(peFixture(t, tt.fixture...))
			require.NoError(t, err)

			if d := cmp.Diff(tt.want, f.VersionResources); d != "" {
				t.Errorf("unexpected version resources (-want +got): %s", d)
			}
		})
	}
}

func Test_Read_MultiLanguageVersionResources_IsDeterministic(t *testing.T) {
	// version resources are collected into a map keyed by language, so the selection must not depend on Go's
	// randomized map iteration order.
	fixture := []languageResource{
		{lang: 0x0407, fields: germanFields},
		{lang: 0x0c0a, fields: spanishFields},
		{lang: 0x0816, fields: portugueseFields},
	}

	for i := 0; i < 25; i++ {
		f, err := Read(peFixture(t, fixture...))
		require.NoError(t, err)
		require.Equal(t, germanFields, f.VersionResources)
	}
}

func Test_Read_MultipleStringTablesInOneBlock(t *testing.T) {
	// a single VS_VERSIONINFO block may hold one string table per language, which is the second way a binary
	// can end up with several translations of the same keys.
	f, err := Read(peFixture(t, languageResource{
		lang: 0x0409,
		tables: []stringTable{
			{key: "0c0a04b0", fields: spanishFields},
			{key: "040904b0", fields: englishFields},
			{key: "040704b0", fields: germanFields},
		},
	}))
	require.NoError(t, err)

	if d := cmp.Diff(englishFields, f.VersionResources); d != "" {
		t.Errorf("unexpected version resources (-want +got): %s", d)
	}
}

func Test_Read_VersionResourcesWithoutStringTables(t *testing.T) {
	// VS_FIXEDFILEINFO is mandatory while string tables are not, so a version resource with no strings at all
	// still describes a file version.
	f, err := Read(peFixture(t, languageResource{lang: 0x0409}))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"FileVersion": "2.1.0.0"}, f.VersionResources)
}

func Test_parseVersionResourceSection_TruncatedResource(t *testing.T) {
	// a block that claims to be longer than the bytes that follow it must not keep the parser reading past the
	// end of the resource: the reads stop returning data, so nothing advances the offsets towards the claimed
	// length. Every truncation of a well-formed resource is exercised here, since only some of them leave the
	// parser inside a block that still has a length left to satisfy.
	res := versionInfoResource(languageResource{lang: 0x0409, fields: englishFields})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 1; n <= len(res); n++ {
			_ = parseVersionResourceSection(bytes.NewReader(res[:n]), newVersionResourceTables(), langIDEnglishUS)
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("parsing a truncated version resource did not terminate")
	}
}

func Test_languageFromStringTableKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		directory uint16
		want      resourceLanguage
	}{
		{
			name:      "language and codepage",
			key:       "040904b0",
			directory: 0x0c0a,
			want:      resourceLanguage{directory: 0x0c0a, table: 0x0409},
		},
		{
			name:      "uppercase hex",
			key:       "0C0A04B0",
			directory: 0x0409,
			want:      resourceLanguage{directory: 0x0409, table: 0x0c0a},
		},
		{
			name:      "language-neutral table falls back to the directory language",
			key:       "000004b0",
			directory: 0x0409,
			want:      resourceLanguage{directory: 0x0409, table: 0x0000},
		},
		{
			name:      "key too short to state a language",
			key:       "04b0",
			directory: 0x0409,
			want:      resourceLanguage{directory: 0x0409, table: 0x04b0},
		},
		{
			name:      "empty key",
			key:       "",
			directory: 0x0409,
			want:      resourceLanguage{directory: 0x0409},
		},
		{
			name:      "non-hex key",
			key:       "StringFileInfo",
			directory: 0x0409,
			want:      resourceLanguage{directory: 0x0409},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, languageFromStringTableKey(tt.key, tt.directory))
		})
	}
}

func Test_resourceLanguage_effective(t *testing.T) {
	assert.Equal(t, uint16(0x0409), resourceLanguage{directory: 0x0c0a, table: 0x0409}.effective(), "the table states its own language")
	assert.Equal(t, uint16(0x0c0a), resourceLanguage{directory: 0x0c0a}.effective(), "the directory entry is the fallback")
	assert.Equal(t, langIDNeutral, resourceLanguage{}.effective(), "nothing states a language")
}

func Test_versionResourceTables_preferred_ignoresEmptyTables(t *testing.T) {
	tables := newVersionResourceTables()
	tables.fields(resourceLanguage{table: langIDEnglishUS}) // present, but empty
	tables.fields(resourceLanguage{table: 0x0c0a})["ProductName"] = "Instalador de paquetes de controladores"

	assert.Equal(t, map[string]string{"ProductName": "Instalador de paquetes de controladores"}, tables.preferred())
}

func Test_versionResourceTables_preferred_noTables(t *testing.T) {
	assert.Empty(t, newVersionResourceTables().preferred())
}

var (
	englishFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Driver Package Installer",
		"FileVersion":     "2.1",
		"ProductName":     "Driver Package Installer (DPInst)",
	}

	spanishFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Instalador de paquetes de controladores",
		"FileVersion":     "2.1",
		"ProductName":     "Instalador de paquetes de controladores (DPInst)",
	}

	germanFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Treiberpaket-Installationsprogramm",
		"FileVersion":     "2.1",
		"ProductName":     "Treiberpaket-Installationsprogramm (DPInst)",
	}

	portugueseFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Instalador de pacote de controladores",
		"FileVersion":     "2.1",
		"ProductName":     "Instalador de pacote de controladores (DPInst)",
	}

	britishFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Driver Package Installer",
		"FileVersion":     "2.1",
		"ProductName":     "Driver Package Installer (DPInst, en-GB)",
	}

	neutralFields = map[string]string{
		"CompanyName":     "Microsoft Corporation",
		"FileDescription": "Driver Package Installer",
		"FileVersion":     "2.1",
		"ProductName":     "Driver Package Installer (DPInst, neutral)",
	}
)

// languageResource describes one VS_VERSIONINFO resource to synthesize, as found under a single language entry
// of the resource directory.
type languageResource struct {
	// lang is the LANGID of the resource directory entry the resource is placed under.
	lang uint16

	// fields is a shorthand for a resource with a single string table; codepageKey overrides that table's szKey.
	fields      map[string]string
	codepageKey string

	// tables, when set, describes several string tables held within the one resource.
	tables []stringTable
}

type stringTable struct {
	key    string
	fields map[string]string
}

func (l languageResource) stringTables() []stringTable {
	if len(l.tables) > 0 {
		return l.tables
	}
	if l.fields == nil {
		return nil
	}
	key := l.codepageKey
	if key == "" {
		key = fmt.Sprintf("%04x04b0", l.lang)
	}
	return []stringTable{{key: key, fields: l.fields}}
}

// peFixture writes a PE file carrying one VS_VERSIONINFO resource per given language and returns a reader over it.
func peFixture(t *testing.T, resources ...languageResource) file.LocationReadCloser {
	t.Helper()

	byLanguage := make(map[uint16][]byte, len(resources))
	for _, r := range resources {
		require.NotContains(t, byLanguage, r.lang, "fixture declares the same language twice")
		byLanguage[r.lang] = versionInfoResource(r)
	}

	return peFixtureFromResources(t, byLanguage)
}

func peFixtureFromResources(t *testing.T, byLanguage map[uint16][]byte) file.LocationReadCloser {
	t.Helper()

	path := filepath.Join(t.TempDir(), "fixture.exe")
	require.NoError(t, os.WriteFile(path, buildPE(t, byLanguage), 0600))

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	return file.NewLocationReadCloser(file.NewLocation(path), f)
}

// buildPE assembles the smallest PE32 file that carries version resources: a DOS header, the PE headers, and a
// single .rsrc section holding a type -> name -> language resource tree of RT_VERSION entries.
func buildPE(t *testing.T, byLanguage map[uint16][]byte) []byte {
	t.Helper()

	const (
		rsrcRVA     = 0x1000
		headersSize = 0x400 // where the .rsrc section data begins in the file
	)

	rsrc := buildResourceSection(byLanguage, rsrcRVA)

	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[60:], 64) // e_lfanew

	buf := bytes.NewBuffer(dos)
	buf.WriteString("PE\x00\x00")

	require.NoError(t, binary.Write(buf, binary.LittleEndian, pe.FileHeader{
		Machine:              pe.IMAGE_FILE_MACHINE_I386,
		NumberOfSections:     1,
		SizeOfOptionalHeader: uint16(binary.Size(pe.OptionalHeader32{})),
		Characteristics:      0x0102, // executable, 32 bit
	}))

	optHeader := pe.OptionalHeader32{
		Magic:               0x10b, // PE32
		SectionAlignment:    0x1000,
		FileAlignment:       0x200,
		SizeOfImage:         rsrcRVA + uint32(len(rsrc)),
		SizeOfHeaders:       headersSize,
		NumberOfRvaAndSizes: 16,
	}
	optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE] = pe.DataDirectory{
		VirtualAddress: rsrcRVA,
		Size:           uint32(len(rsrc)),
	}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, optHeader))

	sectionHeader := pe.SectionHeader32{
		VirtualSize:      uint32(len(rsrc)),
		VirtualAddress:   rsrcRVA,
		SizeOfRawData:    uint32(len(rsrc)),
		PointerToRawData: headersSize,
		Characteristics:  0x40000040, // initialized data, readable
	}
	copy(sectionHeader.Name[:], ".rsrc")
	require.NoError(t, binary.Write(buf, binary.LittleEndian, sectionHeader))

	require.Less(t, buf.Len(), headersSize, "PE headers overflowed the space reserved for them")
	buf.Write(make([]byte, headersSize-buf.Len()))
	buf.Write(rsrc)

	return buf.Bytes()
}

// buildResourceSection lays out a resource directory tree of RT_VERSION -> 1 -> LANGID -> data.
func buildResourceSection(byLanguage map[uint16][]byte, rsrcRVA uint32) []byte {
	const (
		directorySize = 16 // IMAGE_RESOURCE_DIRECTORY
		entrySize     = 8  // IMAGE_RESOURCE_DIRECTORY_ENTRY
		dataEntrySize = 16 // IMAGE_RESOURCE_DATA_ENTRY
		rtVersion     = 16
	)

	langs := make([]uint16, 0, len(byLanguage))
	for lang := range byLanguage {
		langs = append(langs, lang)
	}
	// the resource compiler emits directory entries sorted by ID, which is what makes the last entry read the
	// highest-numbered language
	slices.Sort(langs)

	var (
		typeDirOffset = uint32(0)
		nameDirOffset = typeDirOffset + directorySize + entrySize
		langDirOffset = nameDirOffset + directorySize + entrySize
		dataOffset    = langDirOffset + directorySize + entrySize*uint32(len(langs))
		blobOffset    = dataOffset + dataEntrySize*uint32(len(langs))
	)

	buf := new(bytes.Buffer)
	writeDirectory(buf, 1)
	writeDirectoryEntry(buf, rtVersion, nameDirOffset, true)
	writeDirectory(buf, 1)
	writeDirectoryEntry(buf, 1, langDirOffset, true)

	writeDirectory(buf, uint16(len(langs)))
	for i, lang := range langs {
		writeDirectoryEntry(buf, uint32(lang), dataOffset+dataEntrySize*uint32(i), false)
	}

	blobs := blobOffset
	for _, lang := range langs {
		res := byLanguage[lang]
		_ = binary.Write(buf, binary.LittleEndian, peImageResourceDataEntry{
			OffsetToData: rsrcRVA + blobs, // this one is an RVA, unlike every other offset in the tree
			Size:         uint32(len(res)),
		})
		blobs += alignUint32(uint32(len(res)))
	}

	for _, lang := range langs {
		res := byLanguage[lang]
		buf.Write(res)
		buf.Write(make([]byte, alignUint32(uint32(len(res)))-uint32(len(res))))
	}

	return buf.Bytes()
}

func writeDirectory(buf io.Writer, entries uint16) {
	_ = binary.Write(buf, binary.LittleEndian, peImageResourceDirectory{NumberOfIDEntries: entries})
}

func writeDirectoryEntry(buf io.Writer, id, offset uint32, isDirectory bool) {
	if isDirectory {
		offset |= 0x80000000
	}
	_ = binary.Write(buf, binary.LittleEndian, peImageResourceDirectoryEntry{Name: id, OffsetToData: offset})
}

// versionInfoResource builds a VS_VERSIONINFO resource:
//
//	VS_VERSION_INFO -> VS_FIXEDFILEINFO + StringFileInfo -> StringTable(s) -> String(s)
//
// source: https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
func versionInfoResource(r languageResource) []byte {
	fixedFileInfo := new(bytes.Buffer)
	_ = binary.Write(fixedFileInfo, binary.LittleEndian, peVsFixedFileInfo{
		Signature:     0xfeef04bd,
		StructVersion: 0x00010000,
		FileVersionMS: 2<<16 | 1, // 2.1.0.0
	})

	var children [][]byte
	if tables := r.stringTables(); len(tables) > 0 {
		stringTables := make([][]byte, 0, len(tables))
		for _, table := range tables {
			stringTables = append(stringTables, versionInfoBlock(table.key, nil, 0, 1, versionInfoStrings(table.fields)...))
		}
		children = append(children, versionInfoBlock("StringFileInfo", nil, 0, 1, stringTables...))
	}

	return versionInfoBlock("VS_VERSION_INFO", fixedFileInfo.Bytes(), uint16(fixedFileInfo.Len()), 0, children...)
}

func versionInfoStrings(fields map[string]string) [][]byte {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	strings := make([][]byte, 0, len(keys))
	for _, key := range keys {
		value := utf16Bytes(fields[key])
		// for text values wValueLength is a count of UTF-16 code units, including the null terminator
		strings = append(strings, versionInfoBlock(key, value, uint16(len(value)/2), 1))
	}
	return strings
}

// versionInfoBlock assembles the length-prefixed structure that every part of a version resource shares:
// a header, a null-terminated UTF-16 key, an optional value, and optional children, each padded to a DWORD.
func versionInfoBlock(key string, value []byte, valueLength, blockType uint16, children ...[]byte) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, peLenValLenType{ValueLength: valueLength, Type: blockType})
	buf.Write(utf16Bytes(key))
	padToDWORD(buf)
	buf.Write(value)
	padToDWORD(buf)

	for _, child := range children {
		buf.Write(child)
		padToDWORD(buf)
	}

	block := buf.Bytes()
	binary.LittleEndian.PutUint16(block[0:2], uint16(len(block)))
	return block
}

func padToDWORD(buf *bytes.Buffer) {
	buf.Write(make([]byte, alignToDWORD(buf.Len())-buf.Len()))
}

func alignUint32(v uint32) uint32 {
	return uint32(alignToDWORD(int(v)))
}

// utf16Bytes encodes a null-terminated little-endian UTF-16 string, the only string encoding a version resource uses.
func utf16Bytes(s string) []byte {
	codes := utf16.Encode([]rune(s))
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, codes)
	buf.Write([]byte{0, 0})
	return buf.Bytes()
}
