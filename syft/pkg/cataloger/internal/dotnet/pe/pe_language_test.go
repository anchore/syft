package pe

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type localizedTable struct {
	language string
	product  string
	version  string
}

func localizedResource(table localizedTable) []byte {
	buf := new(bytes.Buffer)
	putUTF16 := func(s string) {
		for _, r := range s {
			_ = binary.Write(buf, binary.LittleEndian, uint16(r))
		}
		_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	}
	pad := func() {
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}
	header := func(key string, valueLength uint16) int {
		pad()
		start := buf.Len()
		_ = binary.Write(buf, binary.LittleEndian, [3]uint16{0, valueLength, 1})
		putUTF16(key)
		pad()
		return start
	}
	finish := func(start int) {
		binary.LittleEndian.PutUint16(buf.Bytes()[start:], uint16(buf.Len()-start))
	}
	root := header("VS_VERSION_INFO", 52)
	_ = binary.Write(buf, binary.LittleEndian, peVsFixedFileInfo{
		FileVersionMS: 0x00010002, FileVersionLS: 0x00030004,
	})
	sfi := header("StringFileInfo", 0)
	st := header(table.language, 0)
	for _, field := range [][2]string{{"ProductName", table.product}, {"ProductVersion", table.version}} {
		if field[1] == "" {
			continue
		}
		start := header(field[0], uint16(len(field[1])+1))
		putUTF16(field[1])
		pad()
		finish(start)
	}
	finish(st)
	finish(sfi)
	finish(root)
	return buf.Bytes()
}

func localizedResourceSection(tables []localizedTable) *extractedSection {
	// Distinct language leaves share one directory walk, as in a real VERSIONINFO resource.
	data := make([]byte, 16+24*len(tables))
	le := binary.LittleEndian
	le.PutUint16(data[14:], uint16(len(tables)))
	for i, table := range tables {
		entry := 16 + 8*i
		dataEntry := 16 + 8*len(tables) + 16*i
		le.PutUint32(data[entry:], uint32(i))
		le.PutUint32(data[entry+4:], uint32(dataEntry))
		blob := localizedResource(table)
		le.PutUint32(data[dataEntry:], testSectionRVA+uint32(len(data)))
		le.PutUint32(data[dataEntry+4:], uint32(len(blob)))
		data = append(data, blob...)
	}
	return &extractedSection{RVA: testSectionRVA, Size: uint32(len(data)), Reader: bytes.NewReader(data)}
}

func TestParseResourceDirectory_LanguagePreference(t *testing.T) {
	english := localizedTable{"040904b0", "Driver Package Installer", "2.1"}
	spanish := localizedTable{"0C0A04B0", "Instalador", "2.1"}
	french := localizedTable{"040C04B0", "Installateur", "2.1"}
	tests := []struct {
		name    string
		tables  []localizedTable
		product string
		version string
	}{
		{"english first", []localizedTable{english, spanish}, english.product, "2.1"},
		{"english last", []localizedTable{spanish, english}, english.product, "2.1"},
		{"mixed case alternate codepage", []localizedTable{spanish, {"040904E4", "English ANSI", "2.1"}, french}, "English ANSI", "2.1"},
		{"no English keeps first", []localizedTable{spanish, french}, spanish.product, "2.1"},
		{"single language", []localizedTable{spanish}, spanish.product, "2.1"},
		{"missing English field preserves fallback", []localizedTable{spanish, {"040904b0", english.product, ""}}, english.product, "2.1"},
		{"fallback field may arrive later", []localizedTable{{"040904b0", english.product, ""}, spanish}, english.product, "2.1"},
		{"first English wins", []localizedTable{english, {"040904e4", "Other English", "9.9"}}, english.product, "2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			walk, err := parseResourceDirectory(localizedResourceSection(tt.tables))
			require.NoError(t, err)
			assert.Equal(t, tt.product, walk.fields["ProductName"])
			assert.Equal(t, tt.version, walk.fields["ProductVersion"])
			assert.Equal(t, "1.2.3.4", walk.fields["FileVersion"])
		})
	}
}
