package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

type ClassificationCataloger struct {
	classifiers []Classifier
}

func NewClassificationCataloger(classifiers []Classifier) (*ClassificationCataloger, error) {
	return &ClassificationCataloger{
		classifiers: classifiers,
	}, nil
}

func (i *ClassificationCataloger) Catalog(resolver source.FileResolver) (map[source.Coordinates][]Classification, error) {
	results := make(map[source.Coordinates][]Classification)

	numResults := 0
	for _, location := range allRegularFiles(resolver) {
		for _, classifier := range i.classifiers {
			result, err := classifier.Classify(resolver, location)
			if err != nil {
				log.Warnf("file classification cataloger failed with class=%q at location=%+v: %+v", classifier.Class, location, err)
				continue
			}
			if result != nil {
				results[location.Coordinates] = append(results[location.Coordinates], *result)
				numResults++
			}
		}
	}
	log.Debugf("file classifier discovered %d results", numResults)

	return results, nil
}
