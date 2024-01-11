package file

const (
	NoFilesSelection             Selection = "none"
	FilesOwnedByPackageSelection Selection = "owned-by-package"
	AllFilesSelection            Selection = "all"
)

type Selection string
