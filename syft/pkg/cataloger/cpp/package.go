package cpp

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type conanRef struct {
	Name      string
	Version   string
	User      string
	Channel   string
	Revision  string
	PackageID string
	Timestamp string
}

func splitConanRef(ref string) *conanRef {
	// ConanfileEntry ref format is:
	// pkg/0.1@user/channel#rrev%timestamp
	// This method is based on conan's ref.loads method:
	// https://github.com/conan-io/conan/blob/release/2.0/conans/model/recipe_ref.py#L93C21-L93C21

	var cref conanRef

	// timestamp
	tokens := strings.Split(ref, "%")
	text := tokens[0]
	if len(tokens) == 2 {
		cref.Timestamp = tokens[1]
	}

	// package_id
	tokens = strings.Split(text, ":")
	text = tokens[0]
	if len(tokens) == 2 {
		cref.PackageID = tokens[1]
	}

	// revision
	tokens = strings.Split(text, "#")
	ref = tokens[0]
	if len(tokens) == 2 {
		cref.Revision = tokens[1]
	}

	// name and version are always given
	tokens = strings.Split(ref, "@")
	nameAndVersion := strings.Split(tokens[0], "/")
	if len(nameAndVersion) < 2 || nameAndVersion[0] == "" || nameAndVersion[1] == "" {
		return nil
	}
	cref.Name = nameAndVersion[0]
	cref.Version = nameAndVersion[1]
	// user and channel
	if len(tokens) == 2 && tokens[1] != "" {
		tokens = strings.Split(tokens[1], "/")
		if len(tokens) == 2 {
			cref.User = tokens[0]
			cref.Channel = tokens[1]
		}
	}
	return &cref
}

func newConanfilePackage(m pkg.ConanfileEntry, locations ...file.Location) *pkg.Package {
	return newConanPackage(m.Ref, m, locations...)
}

func newConanlockPackage(m pkg.ConanV1LockEntry, locations ...file.Location) *pkg.Package {
	return newConanPackage(m.Ref, m, locations...)
}

func newConanReferencePackage(m pkg.ConanV2LockEntry, locations ...file.Location) *pkg.Package {
	return newConanPackage(m.Ref, m, locations...)
}

func newConaninfoPackage(m pkg.ConaninfoEntry, locations ...file.Location) *pkg.Package {
	return newConanPackage(m.Ref, m, locations...)
}

func newConanPackage(refStr string, metadata any, locations ...file.Location) *pkg.Package {
	ref := splitConanRef(refStr)
	if ref == nil {
		return nil
	}

	p := pkg.Package{
		Name:      ref.Name,
		Version:   ref.Version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(ref),
		Language:  pkg.CPP,
		Type:      pkg.ConanPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return &p
}

func packageURL(ref *conanRef) string {
	qualifiers := packageurl.Qualifiers{}
	if ref.Channel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "channel",
			Value: ref.Channel,
		})
	}
	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		ref.User,
		ref.Name,
		ref.Version,
		qualifiers,
		"",
	).ToString()
}
