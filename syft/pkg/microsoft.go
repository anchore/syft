package pkg

// MicrosoftKbPatch represents a Windows Knowledge Base patch identifier associated with a specific Microsoft product from the MSRC (Microsoft Security Response Center).
// This type captures both the product being patched and the KB article number for the update.
type MicrosoftKbPatch struct {
	// ProductID is MSRC Product ID (e.g. "Windows 10 Version 1703 for 32-bit Systems")
	ProductID string `toml:"product_id" json:"product_id"`

	// Kb is Knowledge Base article number (e.g. "5001028")
	Kb string `toml:"kb" json:"kb"`
}
