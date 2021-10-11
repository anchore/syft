package format

import "io"

type Validator func(reader io.Reader) error
