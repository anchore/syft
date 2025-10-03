package file

// Digest represents a cryptographic hash of file contents.
type Digest struct {
	// Algorithm specifies the hash algorithm used (e.g., "sha256", "md5").
	Algorithm string `json:"algorithm"`

	// Value is the hexadecimal string representation of the hash.
	Value string `json:"value"`
}
