package pkg

type Relations struct {
	// ParentsByFileOwnership lists all parent packages that claim ownership of this package
	ParentsByFileOwnership []ID `json:"parentsByFileOwnership"`
}
