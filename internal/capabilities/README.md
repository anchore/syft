# Cataloger Capabilities Documentation

This documentation describes the format and structure of cataloger capabilities YAML files.

## File Organization

Capabilities are organized as follows:
- **Cataloger capabilities**: Located in `syft/pkg/cataloger/*/capabilities.yaml` (one file per ecosystem, alongside the cataloger source code: `golang/capabilities.yaml`, `python/capabilities.yaml`, etc.)
- **Application configuration**: Located in `internal/capabilities/appconfig.yaml`

Each `capabilities.yaml` file is partially auto-generated. Run `go generate ./internal/capabilities` to regenerate.
- Fields marked **AUTO-GENERATED** will be updated during regeneration
- All **capabilities** sections are **MANUAL** - edit these to describe cataloger behavior

## Capability Sections

There are two types of capability sections depending on cataloger type:

### 1. Generic Catalogers (`type: generic`)
- Have capabilities at the **PARSER level**
- Each parser function has its own capabilities section
- Allows different parsers within the same cataloger to have different capabilities

### 2. Custom Catalogers (`type: custom`)
- Have capabilities at the **CATALOGER level**
- Single capabilities section for the entire cataloger

## Capabilities Format

Capabilities use a field-based format with defaults and optional conditional overrides:

```yaml
capabilities:
  - field: <field-name>           # dot-notation path (e.g., "license", "dependency.depth")
    default: <value>              # value when no conditions match
    conditions:                   # optional - conditional overrides evaluated in order
      - when: {ConfigField: val}  # when these config fields match (AND logic)
        value: <override-value>   # use this value instead
        comment: "explanation"    # optional - why this condition exists
    evidence:                     # optional - source code references
      - "StructName.FieldName"
    comment: "explanation"        # optional - general field explanation
```

## Detector Conditions

Detectors (used by custom catalogers) can have optional conditions that control when they are active. This allows a single cataloger to have different detection behavior based on configuration.

### Structure

```yaml
detectors:
  - method: glob                 # AUTO-GENERATED - detection method
    criteria: ["**/*.jar"]       # AUTO-GENERATED - patterns to match
    comment: "always active"     # MANUAL - optional explanation
  - method: glob
    criteria: ["**/*.zip"]
    conditions:                  # MANUAL - when this detector is active
      - when: {IncludeZipFiles: true}  # config fields that must match
        comment: "optional explanation"
    comment: "ZIP detection requires config"
```

### Notes
- Conditions reference fields from the cataloger's config struct
- Multiple conditions in the array use **OR logic** (any condition can activate)
- Multiple fields in a `when` clause use **AND logic** (all must match)
- Detectors without conditions are always active
- Only custom catalogers support detectors with conditions

## Condition Evaluation

- Conditions are evaluated in array order (first match wins)
- Multiple fields in a `when` clause use **AND logic** (all must match)
- Multiple conditions in the array use **OR logic** (first matching condition)
- If no conditions match, the default value is used

## Capability Fields

Standard capability field names and their value types:

### `license` (boolean)

Whether license information is available.

**Examples:**
```yaml
default: true                 # always available
default: false                # never available
default: false                # requires configuration
  conditions:
    - when: {SearchRemoteLicenses: true}
      value: true
```

### `dependency.depth` (array of strings)

Which dependency depths can be discovered.

**Values:** `direct` (immediate deps), `indirect` (transitive deps)

**Examples:**
```yaml
default: [direct]                    # only immediate dependencies
default: [direct, indirect]          # full transitive closure
default: []                          # no dependency information
```

### `dependency.edges` (string)

Relationships between nodes and completeness of the dependency graph.

**Values:**
- `""` - dependencies found but no edges between them
- `"flat"` - single level of dependencies with edges to root package only
- `"reduced"` - transitive reduction (redundant edges removed)
- `"complete"` - all relationships with accurate direct and indirect edges

**Examples:**
```yaml
default: complete
default: ""
```

### `dependency.kinds` (array of strings)

Types of dependencies that can be discovered.

**Values:** `runtime`, `dev`, `build`, `test`, `optional`

**Examples:**
```yaml
default: [runtime]                   # production dependencies only
default: [runtime, dev]              # production and development
default: [runtime, dev, build]       # all dependency types
default: [runtime]                   # with conditional dev deps
  conditions:
    - when: {IncludeDevDeps: true}
      value: [runtime, dev]
```

### `package_manager.files.listing` (boolean)

Whether file listings are available (which files belong to the package).

**Examples:**
```yaml
default: true
default: false
  conditions:
    - when: {CaptureOwnedFiles: true}
      value: true
```

### `package_manager.files.digests` (boolean)

Whether file digests/checksums are included in listings.

**Examples:**
```yaml
default: true
default: false
```

### `package_manager.package_integrity_hash` (boolean)

Whether a hash for verifying package integrity is available.

**Examples:**
```yaml
default: true
default: false
```

## Examples

### Simple cataloger with no configuration

```yaml
capabilities:
  - name: license
    default: true
    comment: "license field always present in package.json"
  - name: dependency.depth
    default: [direct]
  - name: dependency.edges
    default: ""
  - name: dependency.kinds
    default: [runtime]
    comment: "devDependencies not parsed by this cataloger"
  - name: package_manager.files.listing
    default: false
  - name: package_manager.files.digests
    default: false
  - name: package_manager.package_integrity_hash
    default: false
```

### Cataloger with configuration-dependent capabilities

```yaml
capabilities:
  - name: license
    default: false
    conditions:
      - when: {SearchLocalModCacheLicenses: true}
        value: true
        comment: "searches for licenses in GOPATH mod cache"
      - when: {SearchRemoteLicenses: true}
        value: true
        comment: "fetches licenses from proxy.golang.org"
    comment: "license scanning requires configuration"
  - name: dependency.depth
    default: [direct, indirect]
  - name: dependency.edges
    default: flat
  - name: dependency.kinds
    default: [runtime, dev]
  - name: package_manager.files.listing
    default: false
  - name: package_manager.files.digests
    default: false
  - name: package_manager.package_integrity_hash
    default: true
    evidence:
      - "GolangBinaryBuildinfoEntry.H1Digest"
```
