package json

import "github.com/anchore/syft/syft/pkg"

type Relations struct {
	// ParentsByFileOwnership lists all parent packages that claim ownership of this package
	ParentsByFileOwnership []pkg.ID `json:"parentsByFileOwnership"`
}

func newRelations(r pkg.Relations) Relations {
	parentsByFileOwnership := r.ParentsByFileOwnership
	if parentsByFileOwnership == nil {
		parentsByFileOwnership = make([]pkg.ID, 0)
	}
	return Relations{
		ParentsByFileOwnership: parentsByFileOwnership,
	}
}

func (r Relations) ToRelations() pkg.Relations {
	return pkg.Relations{
		ParentsByFileOwnership: r.ParentsByFileOwnership,
	}
}
