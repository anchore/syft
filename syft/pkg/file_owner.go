package pkg

// FileOwner is the interface that wraps OwnedFiles method.
//
// OwnedFiles returns a list of files that a piece of
// package Metadata indicates are owned by the package.
type FileOwner interface {
	OwnedFiles() []string
}
