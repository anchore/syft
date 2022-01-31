package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/profile"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
)

var (
	attestCmd = &cobra.Command{
		Use:   "attest [SOURCE]",
		Short: "Generate a package SBOM as an attestation to [SOURCE]",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container image as the subject of an attestation.",
		Example: internal.Tprintf(packagesExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "attest",
		}),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
				return fmt.Errorf("cannot profile CPU and memory simultaneously")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return attestExec(cmd, args)
		},
	}
)

func attestExec(_ *cobra.Command, args []string) error {
	writer, err := makeWriter([]string{string(format.AttestationOption)}, appConfig.File)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to attestation destination: %w", err)
		}
	}()

	// can only be an image for attestation
	userInput := args[0]

	return eventLoop(
		attestationExecWorker(userInput, writer),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(userInput string, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		// TODO: lift scheme detection into public to shortcircuit on dir/file
		s, src, err := generateSBOM(userInput, errs)
		if err != nil {
			errs <- err
			return
		}

		// TODO: how to select on user desired format option
		bytes, err := syft.Encode(*s, format.SPDXJSONOption)
		if err != nil {
			errs <- err
			return
		}

		err = generateAttestation(bytes, src)
		if err != nil {
			errs <- err
			return
		}

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(*s) },
		})
	}()
	return errs
}

func generateAttestation(predicate []byte, src *source.Source) error {
	predicateType := in_toto.PredicateSPDX

	h, _ := v1.NewHash(src.Image.Metadata.ManifestDigest)

	sv, err := sign.SignerFromKeyOpts()
	if err != nil {
		return err
	}
	defer sv.Close()

	fmt.Fprintln(os.Stderr, "Using generated sbom as payload")

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    h.Hex,
	})
	if err != nil {
		return err
	}

	_, err = json.Marshal(sh)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	setAttestFlags(attestCmd.Flags())
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// Key options
	flags.StringP(
		"key", "", "",
		"private key to use to sign attestation",
	)
}
