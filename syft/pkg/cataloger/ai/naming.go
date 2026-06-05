package ai

import "path"

// pickSafeTensorsName implements the documented naming precedence chain:
//   - config.json _name_or_path  (path.Base, so "org/Model" → "Model";
//     applies to both dir-scan and OCI groups)
//   - fallback name — the group's source-specific positional identifier
func pickSafeTensorsName(nameOrPath, fallbackName string) string {
	if nameOrPath != "" {
		return path.Base(nameOrPath)
	}
	return fallbackName
}

// safeTensorsDirName returns the directory-scan naming fallback: the base name
// of the group's parent directory (the group key is already that directory).
func safeTensorsDirName(groupKey string) string {
	base := path.Base(groupKey)
	switch base {
	case "/", ".", "":
		return ""
	}
	return base
}
