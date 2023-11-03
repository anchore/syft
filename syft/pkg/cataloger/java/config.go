package java

type Config struct {
	SearchUnindexedArchives bool
	SearchIndexedArchives   bool
	UseNetwork              bool
	MavenBaseURL            string
	MaxParentRecursiveDepth int
}
