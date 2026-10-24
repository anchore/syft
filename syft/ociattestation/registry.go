package ociattestation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

// NewClientForImage binds OCI discovery to the image digest obtained during
// Syft source resolution. It never re-resolves a mutable image tag.
// Registry auth uses go-containerregistry's challenge-aware transport.
func NewClientForImage(ctx context.Context, reference string, description source.Description, opts *image.RegistryOptions) (*Client, string, error) {
	metadata, err := extractImageMetadata(description)
	if err != nil {
		return nil, "", err
	}
	digest := metadata.ManifestDigest
	if !sha256Digest.MatchString(digest) {
		return nil, "", fmt.Errorf("resolved image manifest has invalid digest %q", digest)
	}
	repo, err := resolveImageRepository(reference, metadata, opts)
	if err != nil {
		return nil, "", err
	}
	baseTransport, err := configuredRegistryTransport(opts)
	if err != nil {
		return nil, "", err
	}
	auth, err := registryAuthenticator(repo, opts)
	if err != nil {
		return nil, "", err
	}
	authTransport, err := transport.NewWithContext(ctx, repo.Registry, auth, baseTransport, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, "", fmt.Errorf("establish OCI registry authentication: %w", err)
	}
	return &Client{
		BaseURL:    repo.Scheme() + "://" + repo.RegistryStr(),
		Repository: repo.RepositoryStr(),
		HTTPClient: &http.Client{Transport: authTransport, Timeout: 30 * time.Second},
	}, digest, nil
}

func extractImageMetadata(description source.Description) (source.ImageMetadata, error) {
	switch metadata := description.Metadata.(type) {
	case source.ImageMetadata:
		return metadata, nil
	case *source.ImageMetadata:
		if metadata != nil {
			return *metadata, nil
		}
		return source.ImageMetadata{}, errors.New("image source has nil metadata")
	default:
		return source.ImageMetadata{}, errors.New("attested SBOMs are only supported for container images")
	}
}

func resolveImageRepository(reference string, metadata source.ImageMetadata, opts *image.RegistryOptions) (name.Repository, error) {
	reference = strings.TrimPrefix(reference, "registry:")
	if reference == "" {
		reference = strings.TrimPrefix(metadata.UserInput, "registry:")
	}
	var parseOptions []name.Option
	if opts != nil && opts.InsecureUseHTTP {
		parseOptions = append(parseOptions, name.Insecure)
	}
	ref, err := name.ParseReference(reference, parseOptions...)
	if err != nil {
		return name.Repository{}, fmt.Errorf("parse image registry reference: %w", err)
	}
	repo := ref.Context()
	// Do not resolve mutable tags a second time. Keep the original registry
	// and repository, and only accept matching canonical digest references.
	for _, digest := range metadata.RepoDigests {
		candidate, err := name.ParseReference(digest, parseOptions...)
		if err != nil || candidate.Context().Name() != repo.Name() {
			continue
		}
		if refDigest, ok := candidate.(name.Digest); ok && refDigest.DigestStr() == metadata.ManifestDigest {
			return refDigest.Context(), nil
		}
	}
	return repo, nil
}

func configuredRegistryTransport(opts *image.RegistryOptions) (http.RoundTripper, error) {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport, nil
	}
	cloned := defaultTransport.Clone()
	if opts == nil {
		return cloned, nil
	}
	if opts.InsecureSkipTLSVerify {
		ensureTLSConfig(cloned)
		cloned.TLSClientConfig.InsecureSkipVerify = true // User explicitly configured an insecure registry.
	}
	if opts.CAFileOrDir != "" {
		certPool, err := registryCACertPool(opts.CAFileOrDir)
		if err != nil {
			return nil, err
		}
		ensureTLSConfig(cloned)
		cloned.TLSClientConfig.RootCAs = certPool
	}
	return cloned, nil
}

func ensureTLSConfig(transport *http.Transport) {
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
}

func registryAuthenticator(repo name.Repository, opts *image.RegistryOptions) (authn.Authenticator, error) {
	if opts != nil {
		for _, cred := range opts.Credentials {
			if cred.Authority != "" && cred.Authority != repo.RegistryStr() && cred.Authority != repo.Registry.Name() {
				continue
			}
			if cred.Token != "" {
				return &authn.Bearer{Token: cred.Token}, nil
			}
			if cred.Username != "" || cred.Password != "" {
				return &authn.Basic{Username: cred.Username, Password: cred.Password}, nil
			}
		}
	}
	return authn.DefaultKeychain.Resolve(repo.Registry)
}

func registryCACertPool(location string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA certificates: %w", err)
	}
	paths := []string{location}
	fi, err := os.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("stat registry CA path: %w", err)
	}
	if fi.IsDir() {
		paths, err = filepath.Glob(filepath.Join(location, "*"))
		if err != nil {
			return nil, err
		}
	}
	loaded := false
	for _, path := range paths {
		if !strings.HasSuffix(path, ".crt") && !strings.HasSuffix(path, ".cert") && !strings.HasSuffix(path, ".pem") {
			continue
		}
		cert, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read registry CA certificate: %w", err)
		}
		if pool.AppendCertsFromPEM(cert) {
			loaded = true
		}
	}
	if !loaded {
		return nil, fmt.Errorf("registry CA path %q contains no usable PEM certificates", location)
	}
	return pool, nil
}
