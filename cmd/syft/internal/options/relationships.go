package options

import "github.com/anchore/fangs"

var _ fangs.FieldDescriber = (*relationshipsConfig)(nil)

type relationshipsConfig struct {
	PackageFileOwnership        bool `mapstructure:"package-file-ownership" json:"package-file-ownership" yaml:"package-file-ownership"`
	PackageFileOwnershipOverlap bool `mapstructure:"package-file-ownership-overlap" json:"package-file-ownership-overlap" yaml:"package-file-ownership-overlap"`
}

func defaultRelationshipsConfig() relationshipsConfig {
	return relationshipsConfig{
		PackageFileOwnership:        true,
		PackageFileOwnershipOverlap: true,
	}
}

func (r *relationshipsConfig) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&r.PackageFileOwnership, "include package-to-file relationships that indicate which files are owned by which packages")
	descriptions.Add(&r.PackageFileOwnershipOverlap, "include package-to-package relationships that indicate one package is owned by another due to files claimed to be owned by one package are also evidence of another package's existence")
}
