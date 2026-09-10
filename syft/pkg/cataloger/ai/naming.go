package ai

import "path"

// pickSafeTensorsName implements the documented naming precedence chain:
func pickSafeTensorsName(nameOrPath, fallbackName string) string {
	if nameOrPath != "" {
		return path.Base(nameOrPath)
	}
	return fallbackName
}

// safeTensorsDirName returns the directory-scan naming fallback: the base name
// of the group's parent directory (the group key is already that directory).
func safeTensorsDirName(directory string) string {
	base := path.Base(directory)
	switch base {
	case "/", ".", "":
		return ""
	}
	return base
}
