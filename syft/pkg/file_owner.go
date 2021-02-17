package pkg

type fileOwner interface {
	ownedFiles() []string
}
