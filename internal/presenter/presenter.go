package presenter

import "io"

// Presenter defines the expected behavior for an object responsible for displaying arbitrary input and processed data
// to a given io.Writer.
type Presenter interface {
	Present(io.Writer) error
}
