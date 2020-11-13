package source

type Metadata struct {
	Scope         Scope         // specific perspective to catalog
	Scheme        Scheme        // the source data scheme type (directory or image)
	ImageMetadata ImageMetadata // all image info (image only)
	Path          string        // the root path to be cataloged (directory only)
}
