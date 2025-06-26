package task

import "github.com/anchore/syft/internal/os"

func NewFeatureDetectionTask() Task {
	return NewTask("feature-detection", os.DetectFeatures)
}
