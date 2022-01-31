package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
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

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
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
	// can only be an image for attestation
	userInput := args[0]

	ko := sign.KeyOpts{
		KeyRef: "./cosign.key",
	}

	return eventLoop(
		attestationExecWorker(userInput, ko),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(userInput string, ko sign.KeyOpts) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		// TODO: lift scheme detection into public to shortcircuit on dir/file
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

		err = generateAttestation(bytes, src, ko)
		if err != nil {
			errs <- err
			return
		}
	}()
	return errs
}

// TODO: context object injection
func generateAttestation(predicate []byte, src *source.Source, ko sign.KeyOpts) error {
	predicateType := in_toto.PredicateSPDX

	h, _ := v1.NewHash(src.Image.Metadata.ManifestDigest)

	// TODO: inject command context and cert path
	sv, err := sign.SignerFromKeyOpts(context.Background(), "", ko)
	if err != nil {
		return err
	}
	defer sv.Close()
	// TODO: can we include our own types here?
	wrapped := dsse.WrapSigner(sv, "application/syft.in-toto+json")

	fmt.Fprintln(os.Stderr, "Using generated sbom as payload")

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

	fmt.Println(string(signedPayload))
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
