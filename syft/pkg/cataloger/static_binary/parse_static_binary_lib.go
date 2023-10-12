package static_binary

import (

	//"errors"

	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	// "runtime/debug"
)

// swift package manager has two versions (1 and 2) of the resolved files, the types below describes the serialization strategies for each version
// with its suffix indicating which version its specific to.

type staticBinaryLibCataloger struct {
	licenses staticLicenses
}

func (c *staticBinaryLibCataloger) parseStaticBinaryLib(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	myresolver, _ := resolver.FileContentsByLocation(reader.Location)
	unionReader, err := unionreader.GetUnionReader(myresolver)
	if err != nil {
		return nil, nil, err
	}
	// get our notes.package info and our shared libs
	notes, libs, _ := scanFile(unionReader, reader.RealPath)
	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//TODO: Hardcoded local lib path - change this to use cataloger opts
	libPath := "/opt/dev/int/domains/mf/mom-cpp/install/lib/"
	//parseStaticBinaryLib(metadata, libs, libPath)
	////////////////////////////////////////////////
	//TESTING -
	////////////////////////////////////////////////
	for _, lib := range libs {

		f, _ := os.Open(libPath + lib)
		newUnionReader, _ := unionreader.GetUnionReader(f)
		libnotes, liblibs, _ := scanFile(newUnionReader, lib)
		var libmetadata pkg.StaticBinaryLibraryMetadata
		libnewerr := json.Unmarshal(libnotes, &libmetadata)
		libmetadata.Parent = metadata.Name
		metadata.Deps = append(metadata.Deps, libmetadata.Name)
		if libnewerr != nil {
			fmt.Println("Something bad happened again:")
		}
		fmt.Printf("libs: %v\n", liblibs)
		fmt.Printf("metadata var: %v\n", libmetadata)

	}
	//fmt.Printf("libs: %v\n", libContents)

	//fmt.Printf("libs: %v\n", libs)
	//fmt.Printf("metadata var: %v\n", metadata)
	////////////////////////////////////////////////
	// END TESTING
	////////////////////////////////////////////////

	internal.CloseAndLogError(reader.ReadCloser, reader.RealPath)
	pkgs = append(pkgs, c.buildBinaryPkgLibInfo(resolver, reader.Location, notes, libs)...)

	return pkgs, nil, nil
}
func (c *staticBinaryLibCataloger) buildBinaryPkgLibInfo(resolver file.Resolver, location file.Location, notes []byte, libs []string) []pkg.Package {
	var pkgs []pkg.Package
	if notes == nil {
		return pkgs
	}
	//this is the outter binary
	p := c.newStaticBinaryLibPackage(
		resolver,
		libs,
		notes,
		location,
	)

	pkgs = append(pkgs, p)
	//Add another package for each lib found in addition
	for _, lib := range libs {
		//TODO: Lib package method.
		p = c.newStaticLibraryLibPackage(
			resolver,
			lib,
			notes,
			location,
		)
		pkgs = append(pkgs, p)
	}

	return pkgs
}
