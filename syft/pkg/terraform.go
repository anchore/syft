package pkg

// TerraformLockProviderEntry represents a single provider entry in a Terraform dependency lock file (.terraform.lock.hcl).
type TerraformLockProviderEntry struct {
	// URL is the provider source address (e.g., "registry.terraform.io/hashicorp/aws").
	URL string `hcl:",label" json:"url"`
	// Constraints specifies the version constraints for the provider (e.g., "~> 4.0").
	Constraints string `hcl:"constraints,optional" json:"constraints"`
	// Version is the locked provider version selected during terraform init.
	Version string `hcl:"version" json:"version"`
	// Hashes are cryptographic checksums for the provider plugin archives across different platforms.
	Hashes []string `hcl:"hashes" json:"hashes"`
}
