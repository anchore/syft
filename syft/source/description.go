package source

// Description represents any static source data that helps describe "what" was cataloged.
type Description struct {
	ID       string   `hash:"ignore"` // the id generated from the parent source struct
	Name     string   `hash:"ignore"`
	Version  string   `hash:"ignore"`
	Supplier string   `hash:"ignore"`
	Authors  []Author `hash:"ignore"`
	Metadata interface{}
}

// Author represents an author of the SBOM.
type Author struct {
	Name  string
	Email string
	Type  string // "Person", "Organization", or "Tool"
}
