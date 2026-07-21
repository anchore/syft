package windows

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const windowsGoOS = "windows"
const windowsUNCPathPrefix = "\\\\"
const windowsDriveColon = ":"
const windowsDrivePathTerminator = ":\\"
const windowsUNCPathTerminator = "\\"

func HostRunningOnWindows() bool {
	return runtime.GOOS == windowsGoOS
}

func ToPosix(windowsPath string) (posixPath string) {
	// volume should be encoded at the start (e.g /c/<path>) where c is the volume
	volumeName := filepath.VolumeName(windowsPath)
	pathWithoutVolume := strings.TrimPrefix(windowsPath, volumeName)
	volumeLetter := strings.ToLower(strings.TrimSuffix(volumeName, ":"))

	// translate non-escaped backslash to forwardslash
	translatedPath := strings.ReplaceAll(pathWithoutVolume, "\\", "/")

	// always have `/` as the root... join all components, e.g.:
	// convert: C:\\some\windows\Place
	// into: /c/some/windows/Place
	return path.Clean("/" + strings.Join([]string{volumeLetter, translatedPath}, "/"))
}

func FromPosix(posixPath string) (windowsPath string) {
	// decode the volume (e.g. /c/<path> --> C:\\) - There should always be a volume name.
	// The volume may be a UNC path (e.g. /\\localhost\C$\ --> \\localhost\C$\)
	pathFields := strings.Split(posixPath, "/")
	rootPath := strings.ToUpper(pathFields[1])
	volumeName := AppendRootTerminator(rootPath)

	// translate non-escaped forward slashes into backslashes
	remainingTranslatedPath := strings.Join(pathFields[2:], "\\")

	// combine volume name and backslash components
	return filepath.Clean(volumeName + remainingTranslatedPath)
}

func AppendRootTerminator(rootPath string) string {
	// UNC paths start with \\ => \\localhost\
	// Windows drive paths start with a letter and a colon => C:\
	// See https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths
	// This function should not be used on file paths since it is meant for root directory paths!
	if strings.HasSuffix(rootPath, windowsDrivePathTerminator) {
		return rootPath
	}
	if strings.HasPrefix(rootPath, windowsUNCPathPrefix) || strings.HasSuffix(rootPath, windowsDriveColon) {
		return rootPath + windowsUNCPathTerminator
	}
	return rootPath + windowsDrivePathTerminator
}
