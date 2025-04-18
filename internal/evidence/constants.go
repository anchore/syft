package evidence

// this package exists so that the file package can reference package evidence in tests without creating a circular dependency.

const (
	AnnotationKey        = "evidence"
	PrimaryAnnotation    = "primary"
	SupportingAnnotation = "supporting"
)
