Conversion - __This is an experimental feature__
----------
This command allows users to convert between SBOM formats. It's important to highlight this feature is experimental. Different SBOM formats have different concerns, and data might be lost during conversion.

To convert between two formats simply run:
```sh
syft convert [SBOM file] -o [FOMAT] > [output file]
``` 

## Supported formats
 - Syft json
 - Syft table
 - SPDX 2.2 json
 - SPDX 2.2 tag-value
 - cycloneDX json
 - cycloneDX xml


## Comparing conversions

The process to compare conversion goes like this:
Let `Sn_f1` be a SBOM of format `f1`

S0_f1 ---> S1_f2 ---> S2_f1

This type of comparison is worst than when most users will experience using Syft, however it is a simple way to compare SBOM outputs using file diffs. 

That is how we compare the results for the table below:

| Formats        | Syft | SPDX-json             | SPDX-tagvalue | CycloneDX-json             | CycloneDX-XML |
|----------------|------|-----------------------|---------------|----------------------------|---------------|
| Syft           |      |                       |               |                            |               |
| SPDX-json      |      | minimal metadata loss |               | files & relationships lost |               |
| SPDX-tagvalue  |      |                       |               |                            |               |
| CycloneDX-json |      |                       |               |                            |               |
| CycloneDX-xml  |      |                       |               |                            |               |

### Supported fields across formats
	- Packages (most relevant, because of pURLs)
	- Files (2nd most relevant)
	- Relationships*

*maybe
