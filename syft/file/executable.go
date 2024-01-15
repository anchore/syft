package file

type (
	ExecutableFormat   string
	RelocationReadOnly string
)

const (
	ELF   ExecutableFormat = "elf"
	MachO ExecutableFormat = "macho"
	PE    ExecutableFormat = "pe"

	RelocationReadOnlyNone    RelocationReadOnly = "none"
	RelocationReadOnlyPartial RelocationReadOnly = "partial"
	RelocationReadOnlyFull    RelocationReadOnly = "full"
)

type Executable struct {
	// Format denotes either ELF, Mach-O, or PE
	Format ExecutableFormat `json:"format" yaml:"format" mapstructure:"format"`

	SecurityFeatures *ELFSecurityFeatures `json:"elfSecurityFeatures,omitempty" yaml:"elfSecurityFeatures" mapstructure:"elfSecurityFeatures"`
}

type ELFSecurityFeatures struct {
	SymbolTableStripped bool `json:"symbolTableStripped" yaml:"symbolTableStripped" mapstructure:"symbolTableStripped"`

	// classic protections

	StackCanary                   *bool              `json:"stackCanary,omitempty" yaml:"stackCanary" mapstructure:"stackCanary"`
	NoExecutable                  bool               `json:"nx" yaml:"nx" mapstructure:"nx"`
	RelocationReadOnly            RelocationReadOnly `json:"relRO" yaml:"relRO" mapstructure:"relRO"`
	PositionIndependentExecutable bool               `json:"pie" yaml:"pie" mapstructure:"pie"`
	DynamicSharedObject           bool               `json:"dso" yaml:"dso" mapstructure:"dso"`

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
