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
	"github.com/anchore/syft/internal/log"
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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	attestExample = `  {{.appName}} {{.command}} --output [FORMAT] --key [KEY] alpine:latest

  Supports the following image sources:
    {{.appName}} {{.command}} --key [KEY] yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} --key [KEY] path/to/a/file/or/dir      only for OCI tar or OCI directory

`
	attestSchemeHelp = "\n" + indent + schemeHelpHeader + "\n" + imageSchemeHelp

	attestHelp = attestExample + attestSchemeHelp

	intotoJSONDsseType = `application/vnd.in-toto+json`
)

var attestFormats = []format.Option{format.SPDXJSONOption, format.CycloneDxJSONOption, format.JSONOption}

var (
	attestCmd = &cobra.Command{
		Use:   "attest --output [FORMAT] --key [KEY] [SOURCE]",
		Short: "Generate a package SBOM as an attestation for the given [SOURCE] container image",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from a container image as the predicate of an in-toto attestation",
		Example: internal.Tprintf(attestHelp, map[string]interface{}{
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

func fetchPassword(_ bool) (b []byte, err error) {
	potentiallyPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
	}
	switch {
	case appConfig.Attest.Password != "":
		return []byte(appConfig.Attest.Password), nil
	case potentiallyPipedInput:
		// handle piped in passwords
		pwBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("unable to get password from stdin: %w", err)
		}
		// be resilient to input that may have newline characters (in case someone is using echo without -n)
		cleanPw := strings.TrimRight(string(pwBytes), "\n")
		return []byte(cleanPw), nil
	case internal.IsTerminal():
		return cosign.GetPassFromTerm(false)
	}
	return nil, errors.New("no method available to fetch password")
}

func selectPassFunc(keypath string) (cosign.PassFunc, error) {
	keyContents, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	var fn cosign.PassFunc = func(bool) (b []byte, err error) { return nil, nil }

	_, err = cosign.LoadPrivateKey(keyContents, nil)
	if err != nil {
		fn = fetchPassword
	}

	return fn, nil
}

func attestExec(ctx context.Context, _ *cobra.Command, args []string) error {
	// can only be an image for attestation or OCI DIR
	userInput := args[0]
	si, err := source.NewSourceInput(userInput)
	if err != nil {
		return fmt.Errorf("could not generate source input for attest command: %q", err)
	}

	if si.ParsedScheme != source.ImageScheme {
		return fmt.Errorf("attest command can only be used with image sources but discovered %q when given %q", si.ParsedScheme, userInput)
	}

	if len(appConfig.Output) > 1 {
		return fmt.Errorf("unable to generate attestation for more than one output")
	}

	output := format.ParseOption(appConfig.Output[0])
	predicateType := assertPredicateType(output)
	if predicateType == "" {
		return fmt.Errorf("could not produce attestation predicate for given format: %q. Available formats: %+v", output, attestFormats)
	}

	passFunc, err := selectPassFunc(appConfig.Attest.Key)
	if err != nil {
		return err
	}

	ko := sign.KeyOpts{
		KeyRef:   appConfig.Attest.Key,
		PassFunc: passFunc,
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", ko)
	if err != nil {
		return err
	}
	defer sv.Close()

	return eventLoop(
		attestationExecWorker(si, output, predicateType, sv),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(sourceInput *source.SourceInput, output format.Option, predicateType string, sv *sign.SignerVerifier) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		s, src, err := generateSBOM(sourceInput, source.NewFromRegistry, errs)
		if err != nil {
			errs <- err
			return
		}

		sbomBytes, err := syft.Encode(*s, output)
		if err != nil {
			errs <- err
			return
		}

		err = generateAttestation(sbomBytes, src, sv, predicateType)
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

func generateAttestation(predicate []byte, src *source.Source, sv *sign.SignerVerifier, predicateType string) error {
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
	if err := bindAttestConfigOptions(attestCmd.Flags()); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// key options
	flags.StringP("key", "", "cosign.key",
		"path to the private key file to use for attestation",
	)

	// in-toto attestations only support JSON predicates, so not all SBOM formats that syft can output are supported
	flags.StringP(
		"output", "o", string(format.JSONOption),
		fmt.Sprintf("the SBOM format encapsulated within the attestation, available options=%v", attestFormats),
	)
}

func bindAttestConfigOptions(flags *pflag.FlagSet) error {
	// note: output is not included since this configuration option is shared between multiple subcommands

	if err := viper.BindPFlag("attest.key", flags.Lookup("key")); err != nil {
		return err
	}

	return nil
}
