# CycloneDX Schemas

`syft` generates a CycloneDX Bom output. We want to be able to validate the CycloneDX schemas
(and dependent schemas) against generated syft output. The best way to do this is with `xmllint`,
however, this tool does not know how to deal with references from HTTP, only the local filesystem.
For this reason we've included a copy of all schemas needed to validate `syft` output, modified
to reference local copies of dependent schemas.

You can get the latest schemas from the [CycloneDX specifications repo](https://github.com/CycloneDX/specification/tree/master/schema).

When the spec version is bumped an approach to determining prior modifications is to compare the 
prior spec version (e.g. if updating to 1.7, compare the files in this directory against the 1.6 
equivalents). 

One can also update the schemas and observe the errors in order to make the necessary updates. 
At the time of writing, the cyclonedx.xsd needed modifications to link to the local spdx.xsd, 
and also to changes the minOccurs for a license tag to 0. (The json schema does not require 
modification for the generated file to lint properly, but can simply be copy/pasted).   
