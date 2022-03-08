package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/syftjson"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
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

var attestFormats = []sbom.FormatID{
	syftjson.ID,
	spdx22json.ID,
	cyclonedxjson.ID,
}

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
	si, err := source.ParseInput(userInput, appConfig.Platform, false)
	if err != nil {
		return fmt.Errorf("could not generate source input for attest command: %w", err)
	}

	switch si.Scheme {
	case source.ImageScheme, source.UnknownScheme:
		// at this point we know that it cannot be dir: or file: schemes, so we will assume that the unknown scheme could represent an image
		si.Scheme = source.ImageScheme
	default:
		return fmt.Errorf("attest command can only be used with image sources but discovered %q when given %q", si.Scheme, userInput)
	}

	// if the original detection was from a local daemon we want to short circuit
	// that and attempt to generate the image source from a registry source instead
	switch si.ImageSource {
	case image.UnknownSource, image.OciRegistrySource:
		si.ImageSource = image.OciRegistrySource
	default:
		return fmt.Errorf("attest command can only be used with image sources fetch directly from the registry, but discovered an image source of %q when given %q", si.ImageSource, userInput)
	}

	if len(appConfig.Outputs) > 1 {
		return fmt.Errorf("unable to generate attestation for more than one output")
	}

	format := syft.FormatByName(appConfig.Outputs[0])
	predicateType := formatPredicateType(format)
	if predicateType == "" {
		return fmt.Errorf("could not produce attestation predicate for given format: %q. Available formats: %+v", formatAliases(format.ID()), formatAliases(attestFormats...))
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
		attestationExecWorker(*si, format, predicateType, sv),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet)...,
	)
}

func attestationExecWorker(sourceInput source.Input, format sbom.Format, predicateType string, sv *sign.SignerVerifier) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.NewFromRegistry(sourceInput, appConfig.Registry.ToOptions(), appConfig.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", sourceInput.UserInput, err)
			return
		}

		s, err := generateSBOM(src, errs)
		if err != nil {
			errs <- err
			return
		}

		sbomBytes, err := syft.Encode(*s, format)
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

func formatPredicateType(format sbom.Format) string {
	switch format.ID() {
	case spdx22json.ID:
		return in_toto.PredicateSPDX
	case cyclonedxjson.ID:
		// Tentative see https://github.com/in-toto/attestation/issues/82
		return "https://cyclonedx.org/bom"
	case syftjson.ID:
		return "https://syft.dev/bom"
	default:
		return ""
	}
}

func findValidDigest(digests []string) string {
	// since we are only using the OCI repo provider for this source we are safe that this is only 1 value
	// see https://github.com/anchore/stereoscope/blob/25ebd49a842b5ac0a20c2e2b4b81335b64ad248c/pkg/image/oci/registry_provider.go#L57-L63
	split := strings.Split(digests[0], "sha256:")
	return split[1]
}

func generateAttestation(predicate []byte, src *source.Source, sv *sign.SignerVerifier, predicateType string) error {
	switch len(src.Image.Metadata.RepoDigests) {
	case 0:
		return fmt.Errorf("cannot generate attestation since no repo digests were found; make sure you're passing an OCI registry source for the attest command")
	case 1:
	default:
		return fmt.Errorf("cannot generate attestation since multiple repo digests were found for the image: %+v", src.Image.Metadata.RepoDigests)
	}

	wrapped := dsse.WrapSigner(sv, intotoJSONDsseType)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewBuffer(predicate),
		Type:      predicateType,
		Digest:    findValidDigest(src.Image.Metadata.RepoDigests),
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
		"output", "o", formatAliases(syftjson.ID)[0],
		fmt.Sprintf("the SBOM format encapsulated within the attestation, available options=%v", formatAliases(attestFormats...)),
	)

	flags.StringP(
		"platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)
}

func bindAttestConfigOptions(flags *pflag.FlagSet) error {
	// note: output is not included since this configuration option is shared between multiple subcommands

	if err := viper.BindPFlag("attest.key", flags.Lookup("key")); err != nil {
		return err
	}

	return nil
}
