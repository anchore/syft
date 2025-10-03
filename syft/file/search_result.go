package file

import (
	"fmt"
)

// SearchResult represents a match found during content scanning, such as secret detection.
type SearchResult struct {
	// Classification identifies the type or category of the matched content.
	Classification string `json:"classification"`

	// LineNumber is the 1-indexed line number where the match was found.
	LineNumber int64 `json:"lineNumber"`

	// LineOffset is the character offset from the start of the line where the match begins.
	LineOffset int64 `json:"lineOffset"`

	// SeekPosition is the absolute byte offset from the start of the file.
	SeekPosition int64 `json:"seekPosition"`

	// Length is the size in bytes of the matched content.
	Length int64 `json:"length"`

	// Value optionally contains the actual matched content.
	Value string `json:"value,omitempty"`
}

func (s SearchResult) String() string {
	return fmt.Sprintf("SearchResult(classification=%q seek=%q length=%q)", s.Classification, s.SeekPosition, s.Length)
}
