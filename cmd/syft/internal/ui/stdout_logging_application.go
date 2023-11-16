package ui

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/anchore/clio"
)

const defaultStdoutLogBufferSize = 1024

// StdoutLoggingApplication wraps the provided app in a clio.Application, which captures non-report data
// written to os.Stdout and instead logs it to the internal logger. It also modifies the rootCmd help function
// to restore os.Stdout in order for Cobra to properly print help to stdout
func StdoutLoggingApplication(app clio.Application, rootCmd *cobra.Command) clio.Application {
	return &stdoutLoggingApplication{
		delegate: app,
		rootCmd:  rootCmd,
	}
}

// stdoutLoggingApplication is a clio.Application, which captures data written to os.Stdout prior to the report
// being output and instead sends non-report output to the internal logger
type stdoutLoggingApplication struct {
	delegate clio.Application
	rootCmd  *cobra.Command
}

func (s *stdoutLoggingApplication) ID() clio.Identification {
	return s.delegate.ID()
}

func (s *stdoutLoggingApplication) AddFlags(flags *pflag.FlagSet, cfgs ...any) {
	s.delegate.AddFlags(flags, cfgs...)
}

func (s *stdoutLoggingApplication) SetupCommand(cmd *cobra.Command, cfgs ...any) *cobra.Command {
	return s.delegate.SetupCommand(cmd, cfgs...)
}

func (s *stdoutLoggingApplication) SetupRootCommand(cmd *cobra.Command, cfgs ...any) *cobra.Command {
	return s.delegate.SetupRootCommand(cmd, cfgs...)
}

func (s *stdoutLoggingApplication) Run() {
	// capture everything written to stdout that is not report output
	restoreStdout := capture(&os.Stdout, newLogWriter(), defaultStdoutLogBufferSize)
	defer restoreStdout()

	// need to restore stdout for cobra to properly output help text to the user on stdout
	baseHelpFunc := s.rootCmd.HelpFunc()
	defer s.rootCmd.SetHelpFunc(baseHelpFunc)
	s.rootCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		restoreStdout()
		baseHelpFunc(command, strings)
	})

	s.delegate.Run()
}

var _ clio.Application = (*stdoutLoggingApplication)(nil)
