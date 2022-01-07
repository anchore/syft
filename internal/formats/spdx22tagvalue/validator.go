package spdx22tagvalue

import (
	"io"
)

func validator(reader io.Reader) error {
	_, err := decoder(reader)
	return err
}
