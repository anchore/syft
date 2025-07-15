package pkg

type HomebrewFormula struct {
	Tap         string `json:"tap,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	Description string `json:"description,omitempty"`
}
