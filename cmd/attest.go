package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
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
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] --key [KEY] alpine:latest

  A summary of discovered packages formatted as the predicate to an image attestation

  Supports the following image sources:
    {{.appName}} {{.command}} --key [KEY] yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} --key [KEY] path/to/a/file/or/dir      OCI tar, OCI directory

  {{.schemeHelp}}
`
	intotoJSONDsseType = `application/vnd.in-toto+json`
)

var (
	keyPath           string
	attestationOutput []string
	attestCmd         = &cobra.Command{
		Use:   "attest --output [FORMAT] --key [KEY] [SOURCE]",
		Short: "Generate a package SBOM as an attestation to [SOURCE]",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image or OCI directory as the predicate of an attestation.",
		Example: internal.Tprintf(attestExample, map[string]interface{}{
			"appName":    internal.ApplicationName,
			"command":    "attest",
			"schemeHelp": schemeHelp,
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

func isTerminal() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func passFunc(isPass bool) (b []byte, err error) {
	pw, ok := os.LookupEnv("COSIGN_PASSWORD")
	switch {
	case ok:
		return []byte(pw), nil
	case isTerminal():
		return cosign.GetPassFromTerm(false)
	// Handle piped in passwords.
	default:
		return io.ReadAll(os.Stdin)
	}
}

func hasPassword(keypath string) (cosign.PassFunc, error) {
	keyContents, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	var fn cosign.PassFunc = func(bool) (b []byte, err error) { return nil, nil }

	_, err = cosign.LoadPrivateKey(keyContents, nil)
	if err != nil {
		fn = passFunc
	}

	return fn, nil
}

func attestExec(ctx context.Context, _ *cobra.Command, args []string) error {
	// can only be an image for attestation or OCI DIR
	userInput := args[0]
	fs := afero.NewOsFs()
	parsedScheme, _, _, err := source.DetectScheme(fs, image.DetectSource, userInput)
	if err != nil {
		return err
	}

	if parsedScheme != source.ImageScheme {
		return fmt.Errorf("attestation can only be used with image sources; found %v", parsedScheme)
	}

	passFunc, err := hasPassword(keyPath)
	if err != nil {
		return err
	}

	ko := sign.KeyOpts{
		KeyRef:   keyPath,
		PassFunc: passFunc,
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", ko)
	if err != nil {
		return err
	}
	defer sv.Close()

	return eventLoop(
		attestationExecWorker(userInput, sv),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(userInput string, sv *sign.SignerVerifier) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		if len(attestationOutput) > 1 {
			errs <- fmt.Errorf("can not generate attestation for more than one output")
			return
		}

		output := format.ParseOption(attestationOutput[0])
		if output == format.UnknownFormatOption {
			errs <- fmt.Errorf("can not use %v as attestation format. Try: %v", output, format.AllOptions)
			return
		}

		s, src, err := generateSBOM(userInput, errs)
		if err != nil {
			errs <- err
			return
		}

		bytes, err := syft.Encode(*s, output)
		if err != nil {
			errs <- err
			return
		}

		err = generateAttestation(bytes, src, sv, output)
		if err != nil {
			errs <- err
			return
		}
	}()
	return errs
}

func assertPredicateType(output format.Option) string {
	switch output {
	case format.SPDXJSONOption:
		return in_toto.PredicateSPDX
	// Tentative see https://github.com/in-toto/attestation/issues/82
	case format.CycloneDxJSONOption:
		return "https://cyclonedx.org/bom"
	case format.JSONOption:
		return "https://syft.dev/bom"
	default:
		return ""
	}
}

func generateAttestation(predicate []byte, src *source.Source, sv *sign.SignerVerifier, output format.Option) error {
	predicateType := assertPredicateType(output)
	if predicateType == "" {
		return fmt.Errorf("could not produce attestation predicate for format: %v", output)
	}

	h, err := v1.NewHash(src.Image.Metadata.ManifestDigest)
	if err != nil {
		return errors.Wrap(err, "could not hash manifest digest for image")
	}

	wrapped := dsse.WrapSigner(sv, intotoJSONDsseType)

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
		return errors.Wrap(err, "unable to sign SBOM")
	}

	bus.Publish(partybus.Event{
		Type: event.Exit,
		Value: func() error {
			_, err := os.Stdout.Write(signedPayload)
			return err
		},
	})

	return nil
}

func init() {
	setAttestFlags(attestCmd.Flags())
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// Key options
	flags.StringVarP(&keyPath, "key", "", "cosign.key",
		"path to the private key file to use for attestation",
	)

	flags.StringArrayVarP(&attestationOutput,
		"output", "o", []string{string(format.JSONOption)},
		fmt.Sprintf("SBOM output format, options=%v", format.AllOptions),
	)
}
