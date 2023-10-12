package static_binary

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

type staticBinaryCataloger struct {
	licenses staticLicenses
}

func (c *staticBinaryCataloger) parseStaticBinary(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {

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

	for _, lib := range libs {
		//TODO:
		//First we should check currect directory
		//Next we try lib64
		//then we try ld_library_path variable
		//last we try the options path

		//Get our lib file
		var f *os.File
		var libPath string
		libPath = "./"
		f, fileErr_ := os.Open(libPath + lib)
		if fileErr_ != nil {
			libPath = "/lib64"
			f, fileErr_ = os.Open(libPath + lib)

			if fileErr_ != nil {
				//TODO: get ld_library_path sys var here
				libPath = "/lib64"
				f, fileErr_ = os.Open(libPath + lib)
				if fileErr_ != nil {
					libPath := c.licenses.opts.localSharedLibDir
					f, fileErr_ = os.Open(libPath + lib)
					if fileErr_ != nil {
						fmt.Printf("Error: %v\n", fileErr_)
					}
				}

			}
		}

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
		//fmt.Printf("metadata var: %v\n", libmetadata)

	}

	//fmt.Printf("libs: %v\n", libs)
	//fmt.Printf("metadata var: %v\n", metadata)

	internal.CloseAndLogError(reader.ReadCloser, reader.RealPath)
	pkgs = append(pkgs, c.buildBinaryPkgInfo(resolver, reader.Location, notes, libs)...)

	return pkgs, nil, nil
}

// TODO - This is where we setup the package
func (c *staticBinaryCataloger) buildBinaryPkgInfo(resolver file.Resolver, location file.Location, notes []byte, libs []string) []pkg.Package {
	var pkgs []pkg.Package
	if notes == nil {
		return pkgs
	}
	//this is the outter binary
	p := c.newStaticBinaryPackage(
		resolver,
		libs,
		notes,
		location,
	)

	pkgs = append(pkgs, p)
	//Add another package for each lib found in addition
	for _, lib := range libs {

		p = c.newStaticBinaryLibPackage(
			resolver,
			lib,
			notes,
			location,
		)
		pkgs = append(pkgs, p)
	}

	return pkgs
}
