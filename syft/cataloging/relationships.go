package cataloging

type RelationshipsConfig struct {
	// PackageFileOwnership will include package-to-file relationships that indicate which files are owned by which packages.
	PackageFileOwnership bool `yaml:"package-file-ownership" json:"package-file-ownership" mapstructure:"package-file-ownership"`

	// PackageFileOwnershipOverlap will include package-to-package relationships that indicate one package is owned by another due to files claimed to be owned by one package are also evidence of another package's existence.
	// For example, if an RPM package is installed and claims to own /etc/app/package.lock and a separate NPM package was discovered by cataloging /etc/app/package.lock, then the two packages will
	// have ownership overlap relationship.
	PackageFileOwnershipOverlap bool `yaml:"package-file-ownership-overlap" json:"package-file-ownership-overlap" mapstructure:"package-file-ownership-overlap"`

	// ExcludeBinaryPackagesWithFileOwnershipOverlap will exclude binary packages from the package catalog that are evident by files also owned by another package.
	// For example, if a binary package representing the /bin/python binary is discovered and there is a python RPM package installed which claims to
	// orn /bin/python, then the binary package will be excluded from the catalog altogether if this configuration is set to true.
	ExcludeBinaryPackagesWithFileOwnershipOverlap bool `yaml:"exclude-binary-packages-with-file-ownership-overlap" json:"exclude-binary-packages-with-file-ownership-overlap" mapstructure:"exclude-binary-packages-with-file-ownership-overlap"`
}

func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		PackageFileOwnership:                          true,
		PackageFileOwnershipOverlap:                   true,
		ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
	}
}

func (c RelationshipsConfig) WithPackageFileOwnership(ownership bool) RelationshipsConfig {
	c.PackageFileOwnership = ownership
	return c
}

func (c RelationshipsConfig) WithPackageFileOwnershipOverlap(overlap bool) RelationshipsConfig {
	c.PackageFileOwnershipOverlap = overlap
	return c
}

func (c RelationshipsConfig) WithExcludeBinaryPackagesWithFileOwnershipOverlap(exclude bool) RelationshipsConfig {
	c.ExcludeBinaryPackagesWithFileOwnershipOverlap = exclude
	return c
}
