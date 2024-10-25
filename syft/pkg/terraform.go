package pkg

// TerraformLockEntry represents a single entry in a Terraform dependency lock file (.terraform.lock.hcl).
type TerraformLockEntry struct {
	URL         string   `hcl:",label" json:"url"`
	Constraints string   `hcl:"constraints" json:"constraints"`
	Version     string   `hcl:"version" json:"version"`
	Hashes      []string `hcl:"hashes" json:"hashes"`
}
