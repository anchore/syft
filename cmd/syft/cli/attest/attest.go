package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/wagoodman/go-partybus"

	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	allowedAttestFormats = []sbom.FormatID{
		syftjson.ID,
		spdx22json.ID,
		cyclonedxjson.ID,
	}

	intotoJSONDsseType = `application/vnd.in-toto+json`
)

func Run(ctx context.Context, app *config.Application, ko sign.KeyOpts, args []string) error {
	// We cannot generate an attestation for more than one output
	if len(app.Outputs) > 1 {
		return fmt.Errorf("unable to generate attestation for more than one output")
	}

	// can only be an image for attestation or OCI DIR
	userInput := args[0]
	si, err := parseImageSource(userInput, app)
	if err != nil {
		return err
	}

	format := syft.FormatByName(app.Outputs[0])
	predicateType := formatPredicateType(format)
	if predicateType == "" {
		return fmt.Errorf(
			"could not produce attestation predicate for given format: %q. Available formats: %+v",
			options.FormatAliases(format.ID()),
			options.FormatAliases(allowedAttestFormats...),
		)
	}

	if app.Attest.KeyRef != "" {
		passFunc, err := selectPassFunc(app.Attest.KeyRef, app.Attest.Password)
		if err != nil {
			return err
		}

		ko.PassFunc = passFunc
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return err
	}
	defer sv.Close()

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, format, predicateType, sv),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func parseImageSource(userInput string, app *config.Application) (s *source.Input, err error) {
	si, err := source.ParseInput(userInput, app.Platform, false)
	if err != nil {
		return nil, fmt.Errorf("could not generate source input for attest command: %w", err)
	}

	switch si.Scheme {
	case source.ImageScheme, source.UnknownScheme:
		// at this point we know that it cannot be dir: or file: schemes;
		// we will assume that the unknown scheme could represent an image;
		si.Scheme = source.ImageScheme
	default:
		return nil, fmt.Errorf("attest command can only be used with image sources but discovered %q when given %q", si.Scheme, userInput)
	}

	// if the original detection was from the local daemon we want to short circuit
	// that and attempt to generate the image source from its current registry source instead
	switch si.ImageSource {
	case image.UnknownSource, image.OciRegistrySource:
		si.ImageSource = image.OciRegistrySource
	default:
		return nil, fmt.Errorf("attest command can only be used with image sources fetch directly from the registry, but discovered an image source of %q when given %q", si.ImageSource, userInput)
	}

	return si, nil
}

func execWorker(app *config.Application, sourceInput source.Input, format sbom.Format, predicateType string, sv *sign.SignerVerifier) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.NewFromRegistry(sourceInput, app.Registry.ToOptions(), app.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", sourceInput.UserInput, err)
			return
		}

		s, err := packages.GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		sbomBytes, err := syft.Encode(*s, format)
		if err != nil {
			errs <- err
			return
		}

		err = generateAttestation(app, sbomBytes, src, sv, predicateType)
		if err != nil {
			errs <- err
			return
		}
	}()
	return errs
}

func generateAttestation(app *config.Application, predicate []byte, src *source.Source, sv *sign.SignerVerifier, predicateType string) error {
	switch len(src.Image.Metadata.RepoDigests) {
	case 0:
		return fmt.Errorf("cannot generate attestation since no repo digests were found; make sure you're passing an OCI registry source for the attest command")
	case 1:
	default:
		return fmt.Errorf("cannot generate attestation since multiple repo digests were found for the image: %+v", src.Image.Metadata.RepoDigests)
	}

	wrapped := dsse.WrapSigner(sv, intotoJSONDsseType)
	ref, err := name.ParseReference(src.Metadata.ImageMetadata.UserInput)
	if err != nil {
		return err
	}

	digest, err := ociremote.ResolveDigest(ref)
	if err != nil {
		return err
	}

	h, _ := v1.NewHash(digest.Identifier())

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

	// We want to give the option to not upload the generated attestation
	// if passed or if the user is using local PKI
	if app.Attest.NoUpload || app.Attest.KeyRef != "" {
		bus.Publish(partybus.Event{
			Type: event.Exit,
			Value: func() error {
				_, err := os.Stdout.Write(signedPayload)
				return err
			},
		})
		return nil
	}

	return uploadAttestation(app, signedPayload, digest, sv)
}

func trackUploadAttestation() (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.UploadAttestation,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       stage,
			Progressable: prog,
		}),
	})

	return stage, prog
}

// uploads signed SBOM payload to Rekor transparency log along with key information;
// returns a bundle for attestation annotations
// rekor bundle includes a signed payload and rekor timestamp;
// the bundle is then wrapped onto an OCI signed entity and uploaded to
// the user's image's OCI registry repository as *.att
func uploadAttestation(app *config.Application, signedPayload []byte, digest name.Digest, sv *sign.SignerVerifier) error {
	// add application/vnd.dsse.envelope.v1+json as media type for other applications to decode attestation
	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	stage, prog := trackUploadAttestation()
	defer prog.SetCompleted() // just in case we return early

	prog.Total = 2
	stage.Current = "uploading signing information to transparency log"

	// uploads payload to Rekor transparency log along with key information;
	// returns bundle for attesation annotations
	// rekor bundle includes a signed payload and rekor timestamp;
	// the bundle is then wrapped onto an OCI signed entity and uploaded to
	// the user's image's OCI registry repository as *.att
	bundle, err := uploadToTlog(context.TODO(), sv, app.Attest.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
		return cosign.TLogUploadInTotoAttestation(context.TODO(), r, signedPayload, b)
	})
	if err != nil {
		return err
	}

	prog.N = 1
	stage.Current = "uploading attestation to OCI registry"

	// add bundle OCI attestation that is uploaded to
	opts = append(opts, static.WithBundle(bundle))
	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest)
	if err != nil {
		return err
	}

	newSE, err := mutate.AttachAttestationToEntity(se, sig)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	err = ociremote.WriteAttestations(digest.Repository, newSE)
	if err != nil {
		return err
	}

	prog.SetCompleted()

	bus.Publish(partybus.Event{
		Type: event.Exit,
		Value: func() error {
			return nil
		},
	})
	return nil
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

type tlogUploadFn func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*cbundle.RekorBundle, error) {
	var rekorBytes []byte
	// Upload the cert or the public key, depending on what we have
	if sv.Cert != nil {
		rekorBytes = sv.Cert
	} else {
		pemBytes, err := sigs.PublicKeyPem(sv, signatureoptions.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		rekorBytes = pemBytes
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}

	if entry.LogIndex != nil {
		log.Debugf("transparency log entry created with index: %v", *entry.LogIndex)
	}
	return cbundle.EntryToBundle(entry), nil
}
