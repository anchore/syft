package spdx22json

import (
	"encoding/json"
	"fmt"
	"io"
)

func validator(reader io.Reader) error {
	type Document struct {
		SPDXID string `json:"SPDXID"`
	}

	var doc Document
	if err := json.NewDecoder(reader).Decode(&doc); err != nil {
		return fmt.Errorf("unable to decode: %w", err)
	}

	if doc.SPDXID != "" {
		return nil
	}
	return fmt.Errorf("could not extract document SPDXID")
}
