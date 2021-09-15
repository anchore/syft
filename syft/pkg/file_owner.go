package pkg

// FileOwner is the interface that wraps OwnedFiles method.
//
// OwnedFiles returns a list of files that a piece of
// pacakge Metadata indicates are owned by the pacakge.
type FileOwner interface {
	OwnedFiles() []string
}
