package file

type (
	// ExecutableFormat represents the binary executable format type.
	ExecutableFormat string

	// RelocationReadOnly indicates the RELRO security protection level applied to an ELF binary.
	RelocationReadOnly string
)

const (
	ELF   ExecutableFormat = "elf"   // Executable and Linkable Format used on Unix-like systems
	MachO ExecutableFormat = "macho" // Mach object file format used on macOS and iOS
	PE    ExecutableFormat = "pe"    // Portable Executable format used on Windows

	RelocationReadOnlyNone    RelocationReadOnly = "none"    // no RELRO protection
	RelocationReadOnlyPartial RelocationReadOnly = "partial" // partial RELRO protection
	RelocationReadOnlyFull    RelocationReadOnly = "full"    // full RELRO protection
)

// Executable contains metadata about binary files and their security features.
type Executable struct {
	// Format denotes either ELF, Mach-O, or PE
	Format ExecutableFormat `json:"format" yaml:"format" mapstructure:"format"`

	// HasExports indicates whether the binary exports symbols.
	HasExports bool `json:"hasExports" yaml:"hasExports" mapstructure:"hasExports"`

	// HasEntrypoint indicates whether the binary has an entry point function.
	HasEntrypoint bool `json:"hasEntrypoint" yaml:"hasEntrypoint" mapstructure:"hasEntrypoint"`

	// ImportedLibraries lists the shared libraries required by this executable.
	ImportedLibraries []string `json:"importedLibraries" yaml:"importedLibraries" mapstructure:"importedLibraries"`

	// ELFSecurityFeatures contains ELF-specific security hardening information when Format is ELF.
	ELFSecurityFeatures *ELFSecurityFeatures `json:"elfSecurityFeatures,omitempty" yaml:"elfSecurityFeatures" mapstructure:"elfSecurityFeatures"`
}

// ELFSecurityFeatures captures security hardening and protection mechanisms in ELF binaries.
type ELFSecurityFeatures struct {
	// SymbolTableStripped indicates whether debugging symbols have been removed.
	SymbolTableStripped bool `json:"symbolTableStripped" yaml:"symbolTableStripped" mapstructure:"symbolTableStripped"`

	// StackCanary indicates whether stack smashing protection is enabled.
	StackCanary *bool `json:"stackCanary,omitempty" yaml:"stackCanary" mapstructure:"stackCanary"`

	// NoExecutable indicates whether NX (no-execute) protection is enabled for the stack.
	NoExecutable bool `json:"nx" yaml:"nx" mapstructure:"nx"`

	// RelocationReadOnly indicates the RELRO protection level.
	RelocationReadOnly RelocationReadOnly `json:"relRO" yaml:"relRO" mapstructure:"relRO"`

	// PositionIndependentExecutable indicates whether the binary is compiled as PIE.
	PositionIndependentExecutable bool `json:"pie" yaml:"pie" mapstructure:"pie"`

	// DynamicSharedObject indicates whether the binary is a shared library.
	DynamicSharedObject bool `json:"dso" yaml:"dso" mapstructure:"dso"`

	// LlvmSafeStack represents a compiler-based security mechanism that separates the stack into a safe stack for storing return addresses and other critical data, and an unsafe stack for everything else, to mitigate stack-based memory corruption errors
	// see https://clang.llvm.org/docs/SafeStack.html
	LlvmSafeStack *bool `json:"safeStack,omitempty" yaml:"safeStack" mapstructure:"safeStack"`

	// ControlFlowIntegrity represents runtime checks to ensure a program's control flow adheres to the legal paths determined at compile time, thus protecting against various types of control-flow hijacking attacks
	// see https://clang.llvm.org/docs/ControlFlowIntegrity.html
	LlvmControlFlowIntegrity *bool `json:"cfi,omitempty" yaml:"cfi" mapstructure:"cfi"`

	// ClangFortifySource is a broad suite of extensions to libc aimed at catching misuses of common library functions
	// see https://android.googlesource.com/platform//bionic/+/d192dbecf0b2a371eb127c0871f77a9caf81c4d2/docs/clang_fortify_anatomy.md
	ClangFortifySource *bool `json:"fortify,omitempty" yaml:"fortify" mapstructure:"fortify"`

	//// Selfrando provides function order shuffling to defend against ROP and other types of code reuse
	//// see https://github.com/runsafesecurity/selfrando
	// Selfrando *bool `json:"selfrando,omitempty" yaml:"selfrando" mapstructure:"selfrando"`
}
