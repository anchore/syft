package pkg

// MicrosoftKbPatch is slightly odd in how it is expected to map onto data.
// This is critical to grasp because there is no MSRC cataloger. The `ProductID`
// field is expected to be the MSRC Product ID, for example:
// "Windows 10 Version 1703 for 32-bit Systems".
// `Kb` is expected to be the actual KB number, for example "5001028"
type MicrosoftKbPatch struct {
	// ProductID is MSRC Product ID (e.g. "Windows 10 Version 1703 for 32-bit Systems")
	ProductID string `toml:"product_id" json:"product_id"`

	// Kb is Knowledge Base article number (e.g. "5001028")
	Kb string `toml:"kb" json:"kb"`
}
