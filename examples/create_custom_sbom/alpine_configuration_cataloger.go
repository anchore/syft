package main

import (
	"context"
	"fmt"
	"io"
	"path"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

/*
  This is a contrived cataloger that attempts to capture useful APK files from the image as if it were a package.
  This isn't a real cataloger, but it is a good example of how to use API elements to create a custom cataloger.
*/

var _ pkg.Cataloger = (*alpineConfigurationCataloger)(nil)

type alpineConfigurationCataloger struct {
}

func newAlpineConfigurationCataloger() pkg.Cataloger {
	return alpineConfigurationCataloger{}
}

func (m alpineConfigurationCataloger) Name() string {
	return "apk-configuration-cataloger"
}

func (m alpineConfigurationCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	version, versionLocations, err := getVersion(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get alpine version: %w", err)
	}
	if len(versionLocations) == 0 {
		// this doesn't mean we should stop cataloging, just that we don't have a version to use, thus no package to raise up
		return nil, nil, nil
	}

	metadata, metadataLocations, err := newAlpineConfiguration(resolver)
	if err != nil {
		return nil, nil, err
	}

	var locations []file.Location
	locations = append(locations, versionLocations...)
	locations = append(locations, metadataLocations...)

	p := newPackage(version, *metadata, locations...)

	return []pkg.Package{p}, nil, nil
}

func newPackage(version string, metadata AlpineConfiguration, locations ...file.Location) pkg.Package {
	return pkg.Package{
		Name:      "alpine-configuration",
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.Type("system-configuration"), // you can make up your own package type here or use an existing one
		Metadata:  metadata,
	}
}

func newAlpineConfiguration(resolver file.Resolver) (*AlpineConfiguration, []file.Location, error) {
	var locations []file.Location

	keys, keyLocations, err := getAPKKeys(resolver)
	if err != nil {
		return nil, nil, err
	}

	locations = append(locations, keyLocations...)

	return &AlpineConfiguration{
		APKKeys: keys,
	}, locations, nil

}

func getVersion(resolver file.Resolver) (string, []file.Location, error) {
	locations, err := resolver.FilesByPath("/etc/alpine-release")
	if err != nil {
		return "", nil, fmt.Errorf("unable to get alpine version: %w", err)
	}
	if len(locations) == 0 {
		return "", nil, nil
	}

	reader, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return "", nil, fmt.Errorf("unable to read alpine version: %w", err)
	}

	version, err := io.ReadAll(reader)
	if err != nil {
		return "", nil, fmt.Errorf("unable to read alpine version: %w", err)
	}

	return string(version), locations, nil
}

func getAPKKeys(resolver file.Resolver) (map[string]string, []file.Location, error) {
	// name-to-content values
	keyContent := make(map[string]string)

	locations, err := resolver.FilesByGlob("/etc/apk/keys/*.rsa.pub")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get apk keys: %w", err)
	}
	for _, location := range locations {
		basename := path.Base(location.RealPath)
		reader, err := resolver.FileContentsByLocation(location)
		content, err := io.ReadAll(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read apk key content at %s: %w", location.RealPath, err)
		}
		keyContent[basename] = string(content)
	}
	return keyContent, locations, nil
}

type AlpineConfiguration struct {
	APKKeys map[string]string `json:"apkKeys" yaml:"apkKeys"`
	// Add more data you want to capture as part of the package metadata here...
}
