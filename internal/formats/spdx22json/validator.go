package spdx22json

import (
	"io"
)

func validator(reader io.Reader) error {
	_, err := decoder(reader)
	return err
}
