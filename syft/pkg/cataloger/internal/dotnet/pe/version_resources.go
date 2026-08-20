package pe

import (
	"strconv"
)

const (
	// langIDNeutral is the LANGID used when a resource is not attributed to any specific language (LANG_NEUTRAL).
	langIDNeutral uint16 = 0x0000

	// langIDEnglishUS is the LANGID for en-US. This is the language most likely to carry the vendor's canonical
	// product naming, which is what downstream CPE and PURL generation is matched against.
	langIDEnglishUS uint16 = 0x0409

	// primaryLangEnglish is the primary language ID shared by every English sublanguage (en-GB, en-AU, en-CA, ...).
	primaryLangEnglish uint16 = 0x0009

	// primaryLangMask masks a LANGID down to its primary language ID (the low 10 bits).
	primaryLangMask uint16 = 0x03FF
)

// resourceLanguage identifies the language a single VERSIONINFO string table was authored in. Two independent
// sources describe this, and they do not always agree:
//
//   - directory: the LANGID of the resource directory entry the VS_VERSIONINFO block was found under. The PE
//     resource tree is organized as type -> name -> language, so localized binaries carry one complete
//     VS_VERSIONINFO block per language.
//   - table: the LANGID declared by the string table itself, whose szKey is the language and codepage the
//     strings are written in (e.g. "040904b0" is en-US in codepage 1200).
type resourceLanguage struct {
	directory uint16
	table     uint16
}

// effective is the LANGID that best describes the strings themselves. The string table's own declaration wins
// when it makes a claim, since a resource compiler is free to place any table under any directory entry; the
// directory entry is the fallback for tables that declare no language (a common convention for binaries that
// ship a single, unlocalized version resource).
func (l resourceLanguage) effective() uint16 {
	if l.table != langIDNeutral {
		return l.table
	}
	return l.directory
}

// rank orders languages by how well they serve package identification, lowest first.
func (l resourceLanguage) rank() int {
	lang := l.effective()
	switch {
	case lang == langIDEnglishUS:
		return 0
	case lang&primaryLangMask == primaryLangEnglish:
		return 1
	case lang == langIDNeutral:
		return 2
	}
	return 3
}

// preferredOver reports whether l should be selected instead of other. Beyond the language ranking this is a
// total order over the LANGIDs involved, so the selection never depends on the order the resource tree happens
// to be walked in.
func (l resourceLanguage) preferredOver(other resourceLanguage) bool {
	switch {
	case l.rank() != other.rank():
		return l.rank() < other.rank()
	case l.effective() != other.effective():
		return l.effective() < other.effective()
	case l.directory != other.directory:
		return l.directory < other.directory
	}
	return l.table < other.table
}

// versionResourceTables holds every VERSIONINFO string table found in a PE file, keyed by the language it was
// authored in. A binary localized into multiple languages carries one string table per language -- usually as
// separate resource directory entries, sometimes as multiple string tables within a single VS_VERSIONINFO block
// -- and every one of them uses the same keys ("ProductName", "FileDescription", ...). Keeping the tables apart
// is what allows a single language to be chosen deterministically, instead of letting whichever language happens
// to be read last overwrite the values read from all the others.
type versionResourceTables struct {
	byLanguage map[resourceLanguage]map[string]string
}

func newVersionResourceTables() *versionResourceTables {
	return &versionResourceTables{
		byLanguage: make(map[resourceLanguage]map[string]string),
	}
}

// fields returns the string table for the given language, creating it the first time that language is seen.
func (v *versionResourceTables) fields(lang resourceLanguage) map[string]string {
	fields, ok := v.byLanguage[lang]
	if !ok {
		fields = make(map[string]string)
		v.byLanguage[lang] = fields
	}
	return fields
}

// preferred returns the string table that best identifies the binary: US English if it is present, then any
// other English variant, then a language-neutral table, and only then the lowest-numbered remaining LANGID.
// Values are never merged across languages -- a mixture of, say, an English ProductName and a Spanish
// FileDescription describes no version resource that actually exists in the file.
func (v *versionResourceTables) preferred() map[string]string {
	var best resourceLanguage
	var bestFields map[string]string

	for lang, fields := range v.byLanguage {
		if len(fields) == 0 {
			continue
		}
		if bestFields == nil || lang.preferredOver(best) {
			best, bestFields = lang, fields
		}
	}

	if bestFields == nil {
		return make(map[string]string)
	}
	return bestFields
}

// languageFromStringTableKey interprets the szKey of a string table as the LANGID and codepage its strings are
// authored in (e.g. "040904b0"). Keys that do not follow the convention leave the language unstated, in which
// case the enclosing resource directory entry is the only remaining source of that information.
func languageFromStringTableKey(key string, directory uint16) resourceLanguage {
	lang := resourceLanguage{directory: directory}

	if len(key) < 4 {
		return lang
	}

	table, err := strconv.ParseUint(key[:4], 16, 16)
	if err != nil {
		return lang
	}

	lang.table = uint16(table)
	return lang
}
