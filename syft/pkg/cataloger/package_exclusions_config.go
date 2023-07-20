package cataloger

type PackageExclusionsConfig struct {
	Exclusions []PackageExclusion
}

type PackageExclusion struct {
	ParentType    string
	ExclusionType string
}
