package pkg

import "strings"

// DependencyCompleteness describes the quality of the current package and if the SBOM contains relationships to
// a complete set of dependencies. We are only concerned with describing the completeness of the dependencies
// relative to the direct dependencies of the package, not the completeness of the entire graph beyond direct
// dependencies. Completeness should apply to packages required by the current package that are non-test and
// non-development dependencies in nature. There is no distinction about build-time vs runtime dependencies.
// Overall completeness is a function of node connectivity within the SBOM graph, it is not sufficient that all
// dependencies exist in the graph to be considered complete, they must have explicit relationships that denote
// each dependency.
type DependencyCompleteness string

const (
	// UnknownDependencyCompleteness indicates that the completeness of the dependencies cannot be considered
	// positively complete or incomplete. This should be used when the dependency resolution mechanism is not
	// well understood, the set of dependencies is unknowable, or no attempt has been made to resolve
	// dependencies (no assertion).
	UnknownDependencyCompleteness DependencyCompleteness = "unknown"

	// CompleteDependencies indicates that the package has all of its direct dependencies resolved and related to
	// this package. Note that any indirect (transitive) dependencies must not be directly linked to this package.
	CompleteDependencies DependencyCompleteness = "complete"

	// CompleteWithIndirectDependencies is a superset of complete. It indicates that the package has all of its direct dependencies
	// resolved as well as some or all of indirect dependencies. What is notable about this is that direct and
	// indirect dependencies are linked directly to this package and are not separable (you cannot distinguish between
	// a direct and indirect dependency from the perspective of this package).
	CompleteWithIndirectDependencies DependencyCompleteness = "complete-with-indirect"

	// IncompleteDependencies indicates that the package is known to not have all of its direct dependencies listed.
	// This is reserved for cases where we know there are a non-zero number of dependencies for a package, but we
	// are not listing them intentionally or because we are unable to resolve them.
	IncompleteDependencies DependencyCompleteness = "incomplete"
)

func ParseDependencyCompleteness(value string) DependencyCompleteness {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(CompleteDependencies):
		return CompleteDependencies
	case string(CompleteWithIndirectDependencies):
		return CompleteWithIndirectDependencies
	case string(IncompleteDependencies):
		return IncompleteDependencies
	default:
		return UnknownDependencyCompleteness
	}
}
