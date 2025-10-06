package file

const (
	NoFilesSelection             Selection = "none"             // no files are selected
	FilesOwnedByPackageSelection Selection = "owned-by-package" // only files owned by packages are selected
	AllFilesSelection            Selection = "all"              // all files are selected
)

// Selection defines which files should be included during cataloging operations.
type Selection string
