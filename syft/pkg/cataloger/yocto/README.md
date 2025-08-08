# Yocto/OpenEmbedded Cataloger

This cataloger provides support for analyzing Yocto/OpenEmbedded build systems and extracting package information from build artifacts.

## Features

### License Manifest Parsing

- Parses `license.manifest` files containing recipe and license information
- Extracts package names, versions, and license details
- Supports various manifest formats and layouts

### BitBake Cache Analysis

- Parses BitBake cache files (`bb_cache.dat`) with full recipe information
- **Smart Dependency Handling**: Automatically detects and uses BitBake Python modules when available
- **Graceful Fallback**: Falls back to basic parsing when BitBake modules are not available
- **Environment Integration**: Supports BITBAKE_HOME and BITBAKE_LIB environment variables
- **Configuration Options**: BitBakeHome and BitBakeLib config parameters for custom installations

### Package Metadata

- Creates comprehensive `YoctoMetadata` for each discovered package
- Includes layer information, dependencies, and recipe details
- Generates proper Package URLs (PURLs) for Yocto packages

## Architecture

### Cataloger Structure

```go
type cataloger struct {
    config Config
}

type Config struct {
    BuildDir    string // Path to Yocto build directory
    BitBakeHome string // Path to BitBake installation directory
    BitBakeLib  string // Path to BitBake library directory
}
```

### Package Detection Flow

1. **Build Directory Detection**: Looks for Yocto indicators (conf/bblayers.conf, tmp/cache, etc.)
2. **License Manifest Parsing**: Extracts packages from license.manifest files
3. **Cache Analysis**: Attempts to parse BitBake cache files with Python helper
4. **Package Creation**: Converts discovered data into standardized package format

## Usage

```go
import "github.com/anchore/syft/syft/pkg/cataloger/yocto"

// Create cataloger with default configuration
cataloger := yocto.NewCataloger(yocto.DefaultConfig())

// Or with custom configuration
config := yocto.Config{
    BuildDir:    "custom/build/path",
    BitBakeHome: "/opt/yocto/bitbake",  // Optional: custom BitBake installation
    BitBakeLib:  "/opt/yocto/bitbake/lib", // Optional: custom BitBake library path
}
cataloger := yocto.NewCataloger(config)

// Use with file resolver
packages, relationships, err := cataloger.Catalog(ctx, resolver)
```

## Test Data

The cataloger includes comprehensive test data:

- `testdata/bb_cache.dat`: Real BitBake cache file for testing
- `testdata/license.manifest`: Sample license manifest
- `testdata/bitbake_layers_output.txt`: Reference output for validation

## Implementation Notes

### BitBake Cache Parsing

The BitBake cache files contain pickled Python objects that depend on the BitBake framework. The enhanced implementation includes:

1. **Python Helper Script**: Dynamically generated script for cache parsing
2. **Smart BitBake Integration**: Automatically detects and uses actual BitBake libraries when available
3. **Environment Detection**: Searches common BitBake installation paths and respects environment variables
4. **Graceful Fallback**: Falls back to basic parsing when BitBake modules are not available
5. **Configurable Paths**: Supports custom BitBake installation paths via configuration

### Layer Detection

Extracts layer information from recipe file paths:

- Recognizes `meta-*` layer patterns
- Handles `openembedded-core` and standard layer names
- Falls back to directory-based detection

### Package URL Generation

Generates PURLs in the format:

```
pkg:openembedded/meta/package-name@version
```

## Validation

The implementation is validated against real Yocto build data:

- Parses actual license.manifest files successfully
- Matches expected recipes from bitbake-layers output
- Handles various edge cases and error conditions
- Maintains compatibility with existing Syft package structures

## Future Enhancements

Potential improvements for cache parsing:

1. **Native Go Implementation**: Direct parsing without Python dependencies
2. **BitBake Integration**: Optional BitBake environment detection and usage
3. **Enhanced Metadata**: Additional recipe information and dependency analysis
4. **Performance Optimization**: Streaming parsing for large cache files

## Testing

Run the test suite:

```bash
go test ./syft/pkg/cataloger/yocto -v
```

Key test categories:

- License manifest parsing
- Cache parsing (with expected limitations)
- Package creation and metadata validation
- Reference data comparison
- Error handling and edge cases
