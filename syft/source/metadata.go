package source

// Metadata represents any static source data that helps describe "what" was cataloged.
type Metadata struct {
	Scheme        Scheme        // the source data scheme type (directory or image)
	ImageMetadata ImageMetadata // all image info (image only)
	Path          string        // the root path to be cataloged (directory only)
}
