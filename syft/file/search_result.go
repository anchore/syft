package file

import (
	"fmt"
)

type SearchResult struct {
	Classification string `json:"classification"`
	LineNumber     int64  `json:"lineNumber"`
	LineOffset     int64  `json:"lineOffset"`
	SeekPosition   int64  `json:"seekPosition"`
	Length         int64  `json:"length"`
	Value          string `json:"value,omitempty"`
}

func (s SearchResult) String() string {
	return fmt.Sprintf("SearchResult(classification=%q seek=%q length=%q)", s.Classification, s.SeekPosition, s.Length)
}
