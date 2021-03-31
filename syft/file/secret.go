package file

import (
	"fmt"
)

type Secret struct {
	PatternName  string `json:"name"`
	LineNumber   int64  `json:"line-number"`
	LineOffset   int64  `json:"line-offset"`
	SeekPosition int64  `json:"position"`
	Length       int64  `json:"length"`
	Value        string `json:"value,omitempty"`
}

func (s Secret) String() string {
	// note: the secret value has purposely been left off to minimize the risk of accidentally revealing the cleartext value
	return fmt.Sprintf("Secret(name=%q position=%q length=%q)", s.PatternName, s.SeekPosition, s.Length)
}
