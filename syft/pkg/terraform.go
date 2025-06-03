package pkg

// TerraformLockProviderEntry represents a single provider entry in a Terraform dependency lock file (.terraform.lock.hcl).
type TerraformLockProviderEntry struct {
	URL         string   `hcl:",label" json:"url"`
	Constraints string   `hcl:"constraints,optional" json:"constraints"`
	Version     string   `hcl:"version" json:"version"`
	Hashes      []string `hcl:"hashes" json:"hashes"`
}
