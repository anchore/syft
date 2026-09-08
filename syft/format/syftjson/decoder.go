package syftjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
)

// identifyTailSize is how much of the end of a document is inspected when identifying it from its trailing schema
// block, before falling back to parsing the whole document.
const identifyTailSize = 2 * 1024 * 1024

var schemaKey = []byte(`"schema"`)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct{}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", err
	}

	id, version := d.Identify(reader)
	if version == "" || id != ID {
		return nil, "", "", fmt.Errorf("not a syft-json document")
	}
	var doc model.Document

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", fmt.Errorf("unable to seek to start of Syft JSON SBOM: %+v", err)
	}

	dec := json.NewDecoder(reader)

	if err = dec.Decode(&doc); err != nil {
		return nil, "", "", fmt.Errorf("unable to decode syft-json document: %w", err)
	}

	if err := checkSupportedSchema(doc.Schema.Version, internal.JSONSchemaVersion); err != nil {
		log.Warn(err)
	}

	return toSyftModel(doc), ID, doc.Schema.Version, nil
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	// fast path: syft writes the schema block as the last key of the document (see model.Document), so for seekable
	// input the format and version can be read from the tail without parsing a potentially very large document.
	// Anything the tail cannot vouch for falls through to the full parse below.
	if rs, ok := r.(io.ReadSeeker); ok {
		if id, version, ok := identifyFromTail(rs); ok {
			return id, version
		}
	}

	type Document struct {
		Schema model.Schema `json:"schema"`
	}

	dec := json.NewDecoder(r)

	var doc Document
	if err := dec.Decode(&doc); err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	if !strings.Contains(doc.Schema.URL, "anchore/syft") {
		// not a syft-json document
		return "", ""
	}

	// note: we support all previous schema versions
	return ID, doc.Schema.Version
}

// identifyFromTail reads at most identifyTailSize bytes from the end of the reader and attempts to identify the
// document from a top-level schema block found there. The reader is returned to its original position afterwards.
func identifyFromTail(rs io.ReadSeeker) (sbom.FormatID, string, bool) {
	start, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", "", false
	}

	end, err := rs.Seek(0, io.SeekEnd)
	if err != nil || end <= start {
		_, _ = rs.Seek(start, io.SeekStart)
		return "", "", false
	}

	tailLen := min(end-start, int64(identifyTailSize))
	tail := make([]byte, tailLen)
	if _, err := rs.Seek(end-tailLen, io.SeekStart); err != nil {
		_, _ = rs.Seek(start, io.SeekStart)
		return "", "", false
	}
	_, readErr := io.ReadFull(rs, tail)

	if _, err := rs.Seek(start, io.SeekStart); err != nil {
		// without the original position the caller cannot safely parse the document afterwards
		log.WithFields("error", err).Debug("unable to restore reader position after inspecting document tail")
		return "", "", false
	}

	if readErr != nil {
		return "", "", false
	}

	return identifyFromTailBytes(tail)
}

// identifyFromTailBytes looks for a syft schema block among the trailing bytes of a JSON document and, when one is
// found directly within the top-level object, returns the format and schema version it declares. The bytes may
// begin anywhere within the document, but must run to its very end.
func identifyFromTailBytes(tail []byte) (sbom.FormatID, string, bool) {
	// find the last "schema" key. An unescaped quote cannot occur inside a JSON string, so a match whose opening
	// quote is not preceded by a backslash is a genuine string token (and a key if a colon follows it).
	idx := len(tail)
	for {
		idx = bytes.LastIndex(tail[:idx], schemaKey)
		if idx <= 0 {
			// not found, or found at the very start of the tail where we cannot tell whether it is escaped
			return "", "", false
		}
		if tail[idx-1] != '\\' {
			break
		}
	}

	rest := bytes.TrimLeft(tail[idx+len(schemaKey):], " \t\r\n")
	if len(rest) == 0 || rest[0] != ':' {
		// a string value that happens to read "schema", not a key
		return "", "", false
	}
	rest = rest[1:]

	var schema model.Schema
	dec := json.NewDecoder(bytes.NewReader(rest))
	if err := dec.Decode(&schema); err != nil {
		return "", "", false
	}

	// the schema block only identifies the document when it belongs to the top-level object
	if !closesTopLevelObject(rest[dec.InputOffset():]) {
		return "", "", false
	}

	if schema.Version == "" || !strings.Contains(schema.URL, "anchore/syft") {
		return "", "", false
	}

	return ID, schema.Version, true
}

// closesTopLevelObject reports whether the given bytes, which follow a value somewhere within a JSON document, run
// to the end of that document closing exactly one enclosing object (and nothing else) at the very end. When true,
// the value they follow sits directly within the top-level object. Braces inside strings are ignored.
func closesTopLevelObject(b []byte) bool {
	var (
		depth    int
		inString bool
		escaped  bool
		closed   bool
	)
	for _, c := range b {
		if closed {
			// only whitespace may follow the top-level object
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				continue
			}
			return false
		}
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}':
			depth--
			if depth == -1 {
				closed = true
			}
		case ']':
			depth--
			if depth == -1 {
				// the enclosing container is an array, not the top-level object
				return false
			}
		}
	}
	return closed
}

func checkSupportedSchema(documentVersion string, parserVersion string) error {
	documentV, err := semver.NewVersion(documentVersion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	parserV, err := semver.NewVersion(parserVersion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	if documentV.GreaterThan(parserV) {
		return fmt.Errorf("document has schema version %s, but parser has older schema version (%s)", documentVersion, parserVersion)
	}

	return nil
}
