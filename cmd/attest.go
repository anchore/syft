package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

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
	"golang.org/x/term"

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] --key [KEY] alpine:latest

  A summary of discovered packages formatted as the predicate to an image attestation

  Supports the following image sources:
    {{.appName}} {{.command}} --key [KEY] yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} --key [KEY] path/to/a/file/or/dir      OCI tar, OCI directory

  You can also explicitly specify the scheme to use:
    {{.appName}} {{.command}}  docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
`
)

var (
	keyPath           string
	attestationOutput []string
	validAttestScheme = []string{
		"docker",
		"docker-archive",
		"oci-archive",
		"oci-dir",
		"registry",
	}
	attestCmd = &cobra.Command{
		Use:   "attest --output [FORMAT] --key [KEY] [SOURCE]",
		Short: "Generate a package SBOM as an attestation to [SOURCE]",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image or OCI directory as the predicate of an attestation.",
		Example: internal.Tprintf(attestExample, map[string]interface{}{
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

func isTerminal() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func getPassFromTerm(confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter password for private key: ")
	pw1, err := term.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pw1, nil
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, "Enter password for private key again: ")
	confirmpw, err := term.ReadPassword(0)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(confirmpw) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}

func passFunc(isPass bool) (b []byte, err error) {
	pw, ok := os.LookupEnv("COSIGN_PASSWORD")
	switch {
	case ok:
		return []byte(pw), nil
	case isTerminal():
		return getPassFromTerm(false)
	// Handle piped in passwords.
	default:
		return io.ReadAll(os.Stdin)
	}
}

func validateScheme(userInput string) error {
	switch {
	case strings.HasPrefix(userInput, "docker"):
		return nil
	case strings.HasPrefix(userInput, "docker-archive"):
		return nil
	case strings.HasPrefix(userInput, "oci-archive"):
		return nil
	case strings.HasPrefix(userInput, "oci-dir"):
		return nil
	case strings.HasPrefix(userInput, "registry"):
		return nil
	default:
		return fmt.Errorf("could not support attestation for %s; please try one of these scheme: %v", userInput, validAttestScheme)
	}
}

func attestExec(ctx context.Context, _ *cobra.Command, args []string) error {
	// can only be an image for attestation or OCI DIR
	userInput := args[0]
	err := validateScheme(userInput)
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
	case format.SPDXTagValueOption, format.SPDXJSONOption:
		return in_toto.PredicateSPDX
	default:
		return in_toto.StatementInTotoV01
	}
}

func generateAttestation(predicate []byte, src *source.Source, sv *sign.SignerVerifier, output format.Option) error {
	predicateType := assertPredicateType(output)

	h, _ := v1.NewHash(src.Image.Metadata.ManifestDigest)

	wrapped := dsse.WrapSigner(sv, "application/vnd.in-toto+json")

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

	return nil
}

func init() {
	setAttestFlags(attestCmd.Flags())
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// Key options
	flags.StringVarP(&keyPath, "key", "", "cosign.key",
		"private key to use to sign attestation",
	)

	flags.StringArrayVarP(&attestationOutput,
		"output", "o", []string{string(format.JSONOption)},
		fmt.Sprintf("attestation output format, options=%v", format.AllOptions),
	)
}
