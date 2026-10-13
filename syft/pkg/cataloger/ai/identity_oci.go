package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"sort"

	gcrname "github.com/google/go-containerregistry/pkg/name"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

// resolveSafeTensorsOCIIdentity handles the OCI-artifact case
func resolveSafeTensorsOCIIdentity(ctx context.Context, resolver file.Resolver, md *pkg.SafeTensorsModelInfo) safeTensorsIdentity {
	ociResolver, ok := resolver.(file.OCIMediaTypeResolver)
	if !ok {
		return safeTensorsIdentity{}
	}

	modelFileLocs, err := ociResolver.FilesByMediaType(dockerAIModelFileMediaType)
	if err != nil {
		log.Debugf("failed to list docker AI model-file layers: %v", err)
	}

	// the resolver returns layers in map order, and the first config / README
	// seen wins below, so sort for a stable result across runs. For OCI
	// artifacts every RealPath is "/", so in practice this is digest order.
	sort.Slice(modelFileLocs, func(i, j int) bool {
		if modelFileLocs[i].RealPath != modelFileLocs[j].RealPath {
			return modelFileLocs[i].RealPath < modelFileLocs[j].RealPath
		}
		return modelFileLocs[i].FileSystemID < modelFileLocs[j].FileSystemID
	})

	var configName, readmeName string
	var readmeLicenses []string
	var supporting []file.Location
	for _, loc := range modelFileLocs {
		cfg, fm := classifyOCIModelFileLayer(resolver, loc)
		switch {
		case cfg != nil:
			applyHFConfig(md, cfg)
			if configName == "" {
				configName = sanitizeModelName(cfg.NameOrPath)
			}
			supporting = append(supporting, loc)
		case fm != nil:
			if len(readmeLicenses) == 0 {
				readmeLicenses = fm.Licenses
			}
			if readmeName == "" {
				readmeName = firstModelName(fm.BaseModel)
			}
			supporting = append(supporting, loc)
		}
	}

	// Precedence: config.json _name_or_path > README base_model.
	nameOrPath := configName
	if nameOrPath == "" {
		nameOrPath = readmeName
	}

	id := safeTensorsIdentity{
		nameOrPath:   nameOrPath,
		fallbackName: ociImageRefBasename(resolver),
		supporting:   supporting,
	}

	// License precedence: a dedicated vnd.docker.ai.license layer
	// outranks the free-text license field in a model card's README frontmatter.
	licLocs, err := ociResolver.FilesByMediaType(dockerAILicenseMediaType)
	if err != nil {
		log.Debugf("failed to list docker AI license layers: %v", err)
	}
	switch {
	case len(licLocs) > 0:
		id.licenses = identifyLicenseLayers(ctx, resolver, licLocs)
		id.supporting = append(id.supporting, licLocs...)
	case len(readmeLicenses) > 0:
		id.licenses = pkg.NewLicensesFromValuesWithContext(ctx, readmeLicenses...)
	}

	return id
}

// ociImageReferencer is the minimal capability ociImageRefBasename needs: a
// resolver that can surface the OCI image reference it was built from. It is
// kept local to this package (rather than exported from the file package) so the
// assertion stays with its only consumer.
type ociImageReferencer interface {
	ImageReference() string
}

func ociImageRefBasename(resolver file.Resolver) string {
	// TODO: we don't think this approach is generalizable quite yet, but we really do need this information.
	// (Ideally we should be NOT be type asserting on the file resolver directly).
	info, ok := resolver.(ociImageReferencer)
	if !ok {
		return ""
	}
	ref := info.ImageReference()
	if ref == "" {
		return ""
	}
	parsed, err := gcrname.ParseReference(ref)
	if err != nil {
		log.Debugf("failed to parse OCI ref %q: %v", ref, err)
		return ""
	}
	return path.Base(parsed.Context().RepositoryStr())
}

// classifyOCIModelFileLayer reads a model.file layer (up to maxModelFileLayerSize)
// and decodes it as either an HF config.json or a README model card's YAML
// frontmatter, based on its leading bytes. It returns whichever it recognized;
// both are nil when the layer is neither, fails to decode, or is JSON that
// doesn't look like an HF config (e.g. generation_config.json). The caller owns precedence and
// metadata enrichment.
func classifyOCIModelFileLayer(resolver file.Resolver, loc file.Location) (*hfConfig, *readmeFrontmatter) {
	rc, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, nil
	}
	defer internal.CloseAndLogError(rc, loc.RealPath)

	buf, err := readBounded(rc, maxModelFileLayerSize)
	if err != nil {
		log.Debugf("failed to read docker AI model-file layer: %v", err)
		return nil, nil
	}
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	switch {
	case bytes.HasPrefix(trimmed, []byte("---")):
		return nil, parseFrontmatter(trimmed)
	case bytes.HasPrefix(trimmed, []byte("{")):
		var cfg hfConfig
		if err := json.Unmarshal(trimmed, &cfg); err != nil || !cfg.looksLikeHF() {
			return nil, nil
		}
		return &cfg, nil
	}
	return nil, nil
}

// identifyLicenseLayers turns Docker AI license-layer locations into pkg.License values.
func identifyLicenseLayers(ctx context.Context, resolver file.Resolver, locs []file.Location) []pkg.License {
	var out []pkg.License
	var scanFallback []file.Location
	for i := range locs {
		loc := locs[i]
		if spdx := readLicenseSPDXIDFromFrontmatter(resolver, loc); spdx != "" {
			out = append(out, pkg.NewLicenseFromFieldsWithContext(ctx, spdx, "", &loc))
			continue
		}
		scanFallback = append(scanFallback, loc)
	}
	if len(scanFallback) > 0 {
		out = append(out, licenses.FindAtLocations(ctx, resolver, scanFallback...)...)
	}
	return out
}

// readLicenseSPDXIDFromFrontmatter reads a bounded prefix of a license-layer
// blob and returns the spdx-id declared in its YAML frontmatter
func readLicenseSPDXIDFromFrontmatter(resolver file.Resolver, loc file.Location) string {
	rc, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return ""
	}
	defer internal.CloseAndLogError(rc, loc.RealPath)

	buf, err := readPrefix(rc, maxLicensePrefixSize)
	if err != nil {
		log.Debugf("failed to read docker AI license layer: %v", err)
		return ""
	}
	return parseLicenseFrontmatter(buf)
}
