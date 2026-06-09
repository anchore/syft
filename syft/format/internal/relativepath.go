package internal

import (
	"fmt"
	"path"
	"strings"
)

func ConvertAbsoluteToRelative(absPath string) (string, error) {
	if !path.IsAbs(absPath) {
		return absPath, nil
	}

	relPath, found := strings.CutPrefix(absPath, "/")
	if !found {
		return "", fmt.Errorf("error calculating relative path: %s", absPath)
	}

	return relPath, nil
}
