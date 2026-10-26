# Syft API Examples

This directory contains examples of how to use the Syft API.

- `create_simple_sbom`: Create a simple SBOM from scratch
- `create_custom_sbom`: Create an SBOM using as much custom configuration as possible, including a custom cataloger implementation
- `decode_sbom`: Take an existing SBOM file (of arbitrary format) and decode it into a Syft SBOM object
- `select_catalogers`: Example demonstrating how to select specific catalogers to run
- `source_detection`: Shows how to detect what to catalog automatically from a user string (e.g. container image vs directory)
- `source_from_image`: Construct a source from only a container image
- `source_from_registry`: Construct a source directly from a container registry

You can run any of these examples from this directory with:

```bash
go run ./DIRECTORY_NAME
```
