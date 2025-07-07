package task

import "github.com/anchore/syft/internal/os"

func NewOSFeatureDetectionTask() Task {
	return NewTask("os-feature-detection", os.DetectFeatures)
}
