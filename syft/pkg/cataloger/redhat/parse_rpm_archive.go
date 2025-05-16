package redhat

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/sassoftware/go-rpmutils"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pgpSig struct {
	_          [3]byte
	Date       int32
	KeyID      [8]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
}

type textSig struct {
	_          [2]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
	_          [4]byte
	Date       int32
	_          [4]byte
	KeyID      [8]byte
}

type pgp4Sig struct {
	_          [2]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
	_          [17]byte
	KeyID      [8]byte
	_          [2]byte
	Date       int32
}

var pubKeyLookup = map[uint8]string{
	0x01: "RSA",
}
var hashLookup = map[uint8]string{
	0x02: "SHA1",
	0x08: "SHA256",
}

// parseRpmArchive parses a single RPM
func parseRpmArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	rpm, err := rpmutils.ReadRpm(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("RPM file found but unable to read: %s (%w)", reader.RealPath, err)
	}

	nevra, err := rpm.Header.GetNEVRA()
	if err != nil {
		return nil, nil, err
	}

	licenses, err := rpm.Header.GetStrings(rpmutils.LICENSE)
	logRpmArchiveErr(reader.Location, "license", err)

	sourceRpm, err := rpm.Header.GetString(rpmutils.SOURCERPM)
	logRpmArchiveErr(reader.Location, "sourcerpm", err)

	vendor, err := rpm.Header.GetString(rpmutils.VENDOR)
	logRpmArchiveErr(reader.Location, "vendor", err)

	digestAlgorithm := getDigestAlgorithm(reader.Location, rpm.Header)

	size, err := rpm.Header.InstalledSize()
	logRpmArchiveErr(reader.Location, "size", err)

	files, err := rpm.Header.GetFiles()
	logRpmArchiveErr(reader.Location, "files", err)

	rsa, err := rpm.Header.GetBytes(rpmutils.SIG_RSA)
	logRpmArchiveErr(reader.Location, "rsa signature", err)

	pgp, err := rpm.Header.GetBytes(rpmutils.SIG_PGP)
	logRpmArchiveErr(reader.Location, "pgp signature", err)

	var allSigs [][]byte
	allSigs = append(allSigs, rsa)
	allSigs = append(allSigs, pgp)
	sigs, err := parseSignatureHeaders(allSigs)
	logRpmArchiveErr(reader.Location, "signature", err)

	metadata := pkg.RpmArchive{
		Name:       nevra.Name,
		Version:    nevra.Version,
		Epoch:      parseEpoch(nevra.Epoch),
		Arch:       nevra.Arch,
		Release:    nevra.Release,
		SourceRpm:  sourceRpm,
		Signatures: sigs,
		Vendor:     vendor,
		Size:       int(size),
		Files:      mapFiles(files, digestAlgorithm),
	}

	return []pkg.Package{newArchivePackage(ctx, reader.Location, metadata, licenses)}, nil, nil
}

func parseSignatureHeaders(data [][]byte) ([]pkg.RpmSignature, error) {
	sigMap := make(map[string]pkg.RpmSignature)
	var keys []string
	for _, sig := range data {
		if len(sig) == 0 {
			continue
		}
		s, err := parsePGP(sig)
		if err != nil {
			log.WithFields("error", err).Trace("unable to parse RPM archive signature")
			return nil, err
		}
		k := s.String()
		if _, ok := sigMap[k]; ok {
			// if we have a duplicate signature, just skip it
			continue
		}
		sigMap[k] = *s
		keys = append(keys, k)
	}
	var signatures []pkg.RpmSignature
	sort.Strings(keys)
	for _, k := range keys {
		signatures = append(signatures, sigMap[k])
	}

	return signatures, nil
}

func parsePGP(data []byte) (*pkg.RpmSignature, error) {
	var tag, signatureType, version uint8

	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, &tag)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &signatureType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}

	switch signatureType {
	case 0x01:
		switch version {
		case 0x1c:
			sig := textSig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, fmt.Errorf("invalid PGP signature on decode: %w", err)
			}
			return &pkg.RpmSignature{
				PublicKeyAlgorithm: pubKeyLookup[sig.PubKeyAlgo],
				HashAlgorithm:      hashLookup[sig.HashAlgo],
				Created:            time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006"),
				IssuerKeyID:        fmt.Sprintf("%x", sig.KeyID),
			}, nil
		default:
			return decodePGPSig(version, r)
		}
	case 0x02:
		return decodePGPSig(version, r)
	}

	return nil, fmt.Errorf("unknown signature type: %d", signatureType)
}

func decodePGPSig(version uint8, r io.Reader) (*pkg.RpmSignature, error) {
	var pubKeyAlgo, hashAlgo, pkgDate string
	var keyID [8]byte

	switch {
	case version > 0x15:
		sig := pgp4Sig{}
		err := binary.Read(r, binary.BigEndian, &sig)
		if err != nil {
			return nil, fmt.Errorf("invalid PGP v4 signature on decode: %w", err)
		}
		pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
		hashAlgo = hashLookup[sig.HashAlgo]
		pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
		keyID = sig.KeyID

	default:
		sig := pgpSig{}
		err := binary.Read(r, binary.BigEndian, &sig)
		if err != nil {
			return nil, fmt.Errorf("invalid PGP signature on decode: %w", err)
		}
		pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
		hashAlgo = hashLookup[sig.HashAlgo]
		pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
		keyID = sig.KeyID
	}
	return &pkg.RpmSignature{
		PublicKeyAlgorithm: pubKeyAlgo,
		HashAlgorithm:      hashAlgo,
		Created:            pkgDate,
		IssuerKeyID:        fmt.Sprintf("%x", keyID),
	}, nil
}

func getDigestAlgorithm(location file.Location, header *rpmutils.RpmHeader) string {
	digestAlgorithm, err := header.GetString(rpmutils.FILEDIGESTALGO)
	logRpmArchiveErr(location, "file digest algo", err)

	if digestAlgorithm != "" {
		return digestAlgorithm
	}
	digestAlgorithms, err := header.GetUint32s(rpmutils.FILEDIGESTALGO)
	logRpmArchiveErr(location, "file digest algo 32-bit", err)

	if len(digestAlgorithms) > 0 {
		digestAlgo := int(digestAlgorithms[0])
		return rpmutils.GetFileAlgoName(digestAlgo)
	}
	return ""
}

func mapFiles(files []rpmutils.FileInfo, digestAlgorithm string) []pkg.RpmFileRecord {
	var out []pkg.RpmFileRecord
	for _, f := range files {
		digest := file.Digest{}
		if f.Digest() != "" {
			digest = file.Digest{
				Algorithm: digestAlgorithm,
				Value:     f.Digest(),
			}
		}
		out = append(out, pkg.RpmFileRecord{
			Path:      f.Name(),
			Mode:      pkg.RpmFileMode(f.Mode()),
			Size:      int(f.Size()),
			Digest:    digest,
			UserName:  f.UserName(),
			GroupName: f.GroupName(),
			Flags:     rpmdb.FileFlags(f.Flags()).String(),
		})
	}
	return out
}

func parseEpoch(epoch string) *int {
	i, err := strconv.Atoi(epoch)
	if err != nil {
		return nil
	}
	return &i
}

func logRpmArchiveErr(location file.Location, operation string, err error) {
	if err != nil {
		log.WithFields("error", err, "operation", operation, "path", location.RealPath).Trace("unable to parse RPM archive")
	}
}
