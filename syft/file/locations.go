package file

import "github.com/anchore/syft/internal/evidence"

type Locations []Location

func (l Locations) Len() int {
	return len(l)
}

func (l Locations) Less(i, j int) bool {
	liEvidence := l[i].Annotations[evidence.AnnotationKey]
	ljEvidence := l[j].Annotations[evidence.AnnotationKey]
	if liEvidence == ljEvidence {
		if l[i].RealPath == l[j].RealPath {
			if l[i].AccessPath == l[j].AccessPath {
				return l[i].FileSystemID < l[j].FileSystemID
			}
			return l[i].AccessPath < l[j].AccessPath
		}
		return l[i].RealPath < l[j].RealPath
	}
	if liEvidence == evidence.PrimaryAnnotation {
		return true
	}
	if ljEvidence == evidence.PrimaryAnnotation {
		return false
	}

	return liEvidence > ljEvidence
}

func (l Locations) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}
