package model

import "encoding/xml"

// Component represents a single element in the CycloneDX BOM
type Component struct {
	XMLName     xml.Name   `xml:"component"`
	Type        string     `xml:"type,attr"`             // Required; Describes if the component is a library, framework, application, container, operating system, firmware, hardware device, or file
	Supplier    string     `xml:"supplier,omitempty"`    // The organization that supplied the component. The supplier may often be the manufacture, but may also be a distributor or repackager.
	Author      string     `xml:"author,omitempty"`      // The person(s) or organization(s) that authored the component
	Publisher   string     `xml:"publisher,omitempty"`   // The person(s) or organization(s) that published the component
	Group       string     `xml:"group,omitempty"`       // The high-level classification that a project self-describes as. This will often be a shortened, single name of the company or project that produced the component, or the source package or domain name.
	Name        string     `xml:"name"`                  // Required; The name of the component as defined by the project
	Version     string     `xml:"version"`               // Required; The version of the component as defined by the project
	Description string     `xml:"description,omitempty"` // A description of the component
	Licenses    *[]License `xml:"licenses>license"`      // A node describing zero or more license names, SPDX license IDs or expressions
	PackageURL  string     `xml:"purl,omitempty"`        // Specifies the package-url (PackageURL). The purl, if specified, must be valid and conform to the specification defined at: https://github.com/package-url/purl-spec
	// TODO: source, hashes, copyright, cpe, purl, swid, modified, pedigree, externalReferences
	// TODO: add user-defined parameters for syft-specific values (image layer index, cataloger, location path, etc.)
}
