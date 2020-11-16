package json

// Distribution provides information about a detected Linux Distribution
type Distribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  string `json:"idLike"`
}
