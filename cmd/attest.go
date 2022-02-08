package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/source"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/pkg/profile"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	keyPath   string
	attestCmd = &cobra.Command{
		Use:   "attest --output [FORMAT] --key [KEY] [SOURCE]",
		Short: "Generate a package SBOM as an attestation to [SOURCE]",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container image as the predicate of an attestation.",
		Example: internal.Tprintf(packagesExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "attest",
		}),
		Args:          validateInputArgs,
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

			return attestExec(cmd.Context(), cmd, args)
		},
	}
)

// TODO: does not play well with TUI interface
func passFunc(isPass bool) (b []byte, err error) {
	return b, err
}

func attestExec(ctx context.Context, _ *cobra.Command, args []string) error {
	// can only be an image for attestation
	// TODO: PR review - best way to validate image OR OCI directory?
	userInput := args[0]

	ko := sign.KeyOpts{
		KeyRef:   keyPath,
		PassFunc: passFunc,
	}

	return eventLoop(
		attestationExecWorker(ctx, userInput, ko),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(ctx context.Context, userInput string, ko sign.KeyOpts) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		// TODO: lift scheme detection into public to shortcircuit on dir/file
		// PR Review - where should we validate?
		s, src, err := generateSBOM(userInput, errs)
		if err != nil {
			errs <- err
			return
		}

		// TODO: currently forced into only SPDX; allow user to specify
		bytes, err := syft.Encode(*s, format.SPDXJSONOption)
		if err != nil {
			errs <- err
			return
		}

		err = generateAttestation(ctx, bytes, src, ko)
		if err != nil {
			errs <- err
			return
		}
	}()
	return errs
}

func generateAttestation(ctx context.Context, predicate []byte, src *source.Source, ko sign.KeyOpts) error {
	predicateType := in_toto.PredicateSPDX

	// TODO: check with OCI format on disk to see if metadata is included
	h, _ := v1.NewHash(src.Image.Metadata.ManifestDigest)

	sv, err := sign.SignerFromKeyOpts(ctx, "", ko)
	if err != nil {
		return err
	}
	defer sv.Close()

	// TODO: can we include our own types here?
	// Should we be specific about the format that is being used as the predicate here?
	wrapped := dsse.WrapSigner(sv, "application/syft.in-toto+json")

	fmt.Fprintln(os.Stdout, "Using generated sbom as payload")

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewBuffer(predicate),
		Type:      predicateType,
		Digest:    h.Hex,
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(context.Background()))
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	bus.Publish(partybus.Event{
		Type: event.Exit,
		Value: func() error {
			_, err := os.Stdout.Write(signedPayload)
			return err
		},
	})

	fmt.Println(string(signedPayload))
	return nil
}

func init() {
	setAttestFlags(attestCmd.Flags())
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// Key options
	flags.StringVarP(&keyPath, "key", "", "",
		"private key to use to sign attestation",
	)
}
