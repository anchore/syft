package model

import "time"

type AnnotationType string

const (
	ReviewerAnnotationType AnnotationType = "REVIEWER"
	OtherAnnotationType    AnnotationType = "OTHER"
)

type Annotation struct {
	// Identify when the comment was made. This is to be specified according to the combined date and time in the
	// UTC format, as specified in the ISO 8601 standard.
	AnnotationDate time.Time `json:"annotationDate"`
	// Type of the annotation
	AnnotationType AnnotationType `json:"annotationType"`
	// This field identifies the person, organization or tool that has commented on a file, package, or the entire document.
	Annotator string `json:"annotator"`
	Comment   string `json:"comment"`
}
