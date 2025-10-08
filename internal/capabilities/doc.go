// Package capabilities provides discovery and tracking of cataloger capabilities.
//
// Run 'go generate' in this directory to discover catalogers from source code and update
// the packages.yaml file with newly discovered generic catalogers.
//
// The packages.yaml file is the source of truth for cataloger capabilities. It contains
// both auto-generated metadata (cataloger names, parser functions, glob patterns) and
// manually-edited capability descriptions (what each cataloger can discover).
package capabilities

//go:generate go run ./generate
