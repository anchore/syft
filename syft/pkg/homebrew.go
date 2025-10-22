package pkg

// HomebrewFormula represents metadata about a Homebrew formula package extracted from formula JSON files.
type HomebrewFormula struct {
	// Tap is Homebrew tap this formula belongs to (e.g. "homebrew/core")
	Tap string `json:"tap,omitempty"`

	// Homepage is the upstream project homepage URL
	Homepage string `json:"homepage,omitempty"`

	// Description is a human-readable formula description
	Description string `json:"description,omitempty"`
}
