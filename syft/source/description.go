package source

// Description represents any static source data that helps describe "what" was cataloged.
type Description struct {
	ID       string `hash:"ignore"` // the id generated from the parent source struct
	Name     string `hash:"ignore"`
	Version  string `hash:"ignore"`
	Supplier string `hash:"ignore"`
	Metadata interface{}
}
