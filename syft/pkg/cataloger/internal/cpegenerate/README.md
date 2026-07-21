# CPE Generation

This package generates Common Platform Enumeration (CPE) identifiers for software packages discovered by Syft.
CPEs are standardized identifiers that enable vulnerability matching by linking packages to known vulnerabilities in databases like the National Vulnerability Database (NVD).

## Overview

CPE generation in Syft uses a **two-tier approach** to balance accuracy and coverage:

1. **Dictionary Lookups** (Authoritative): Pre-validated CPEs from the official NIST CPE dictionary
2. **Heuristic Generation** (Fallback): Intelligent generation based on package metadata and ecosystem-specific patterns

This dual approach ensures:
- **High accuracy** for packages in the NIST dictionary (no false positives)
- **Broad coverage** for packages not yet in the dictionary (maximizes vulnerability detection)
- **Fast performance** with an embedded, indexed CPE dictionary (~814KB)

## Why It Matters

CPEs link discovered packages to security vulnerabilities (CVEs) in tools like Grype. Without accurate CPE generation, vulnerability scanning misses security issues.

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Syft Package Discovery                                 │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  CPE Generation     │
         │  (this package)     │
         └──────────┬──────────┘
                    │
        ┌───────────┴────────────┐
        │                        │
        ▼                        ▼
┌──────────────────┐    ┌─────────────────────┐
│ Dictionary       │    │ Heuristic           │
│ Lookup           │    │ Generation          │
│                  │    │                     │
│ • Embedded index │    │ • Ecosystem rules   │
│ • ~22K entries   │    │ • Vendor/product    │
│ • 11 ecosystems  │    │   candidates        │
└──────────────────┘    │ • Curated mappings  │
                        │ • Smart filters     │
                        └─────────────────────┘
```

### Dictionary Generation Process

The dictionary is generated offline and embedded into the Syft binary for fast, offline lookups.

**Location**: `dictionary/index-generator/`

**Process**:
1. **Fetch**: Retrieves CPE data from NVD Products API using incremental updates
2. **Cache**: Stores raw API responses in ORAS registry for reuse (`.cpe-cache/`)
3. **Filter**:
   - Removes CPEs without reference URLs
   - Excludes hardware (`h`) and OS (`o`) CPEs (keeps only applications `a`)
4. **Index by Ecosystem**:
   - Extracts package names from reference URLs (npm, pypi, rubygems, etc.)
   - Creates index: `ecosystem → package_name → [CPE strings]`
5. **Embed**: Generates `data/cpe-index.json` embedded via `go:embed` directive

### Runtime CPE Lookup/Generation

**Entry Point**: `generate.go`

When Syft discovers a package:

1. **Check for Declared CPEs**: If package metadata already contains CPEs (from SBOM imports), skip generation
2. **Try Dictionary Lookup** (`FromDictionaryFind`):
   - Loads embedded CPE index (singleton, loaded once)
   - Looks up by ecosystem + package name
   - Returns pre-validated CPEs if found
   - Marks source as `NVDDictionaryLookupSource`
3. **Fallback to Heuristic Generation** (`FromPackageAttributes`):
   - Generates vendor/product/targetSW candidates using ecosystem-specific logic
   - Creates CPE permutations from candidates
   - Applies filters to remove known false positives
   - Marks source as `GeneratedSource`

### Supported Ecosystems

**Dictionary Lookups** (11 ecosystems):
npm, RubyGems, PyPI, Jenkins Plugins, crates.io, PHP, Go Modules, WordPress Plugins/Themes

**Heuristic Generation** (all package types):
All dictionary ecosystems plus Java, .NET/NuGet, Alpine APK, Debian/RPM, and any other package type Syft discovers

### Ecosystem-Specific Intelligence

The heuristic generator uses per-ecosystem strategies:

- **Java**: Extracts vendor from groupId, product from artifactId
- **Python**: Parses author fields, adds `_project` suffix variants
- **Go**: Extracts org/repo from module paths (`github.com/org/repo`)
- **JavaScript**: Handles npm scope patterns (`@scope/package`)

### Curated Mappings & Filters

- **500+ curated mappings**: `curl` → `haxx`, `spring-boot` → `pivotal`, etc.
- **Filters**: Prevent false positives (Jenkins plugins vs. core, Jira client vs. server)
- **Validation**: Ensures CPE syntax correctness before returning

## Implementation Details

### Embedded Index Format

```json
{
  "ecosystems": {
    "npm": {
      "lodash": ["cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*"]
    },
    "pypi": {
      "Django": ["cpe:2.3:a:djangoproject:django:*:*:*:*:*:python:*:*"]
    }
  }
}
```

The dictionary generator maps packages to ecosystems using reference URL patterns (npmjs.com, pypi.org, rubygems.org, etc.).

## Maintenance

### Updating the CPE Dictionary

The CPE dictionary should be updated periodically to include new packages:

```bash
# Full workflow: pull cache → update from NVD → build index
make generate:cpe-index

# Or run individual steps:
make generate:cpe-index:cache:pull     # Pull cached CPE data from ORAS
make generate:cpe-index:cache:update   # Fetch updates from NVD Products API
make generate:cpe-index:build          # Generate cpe-index.json from cache
```

**Optional**: Set `NVD_API_KEY` for faster updates (50 req/30s vs 5 req/30s)

This workflow:
1. Pulls existing cache from ORAS registry (avoids re-fetching all ~1.5M CPEs)
2. Fetches only products modified since last update from NVD Products API
3. Builds indexed dictionary (~814KB, ~22K entries)
4. Pushes updated cache for team reuse

### Extending CPE Generation

**Add dictionary support for a new ecosystem:**
1. Add URL pattern in `index-generator/generate.go`
2. Regenerate index with `make generate:cpe-index`

**Improve heuristic generation:**
1. Modify ecosystem-specific file (e.g., `java.go`, `python.go`)
2. Add curated mappings to `candidate_by_package_type.go`

**Key files:**
- `generate.go` - Main generation logic
- `dictionary/` - Dictionary generator and embedded index
- `candidate_by_package_type.go` - Ecosystem-specific candidates
- `filter.go` - Filtering rules
