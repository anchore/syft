package golang

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/kastenhq/goversion/version"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/spillbuf"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

type extendedBuildInfo struct {
	*debug.BuildInfo
	cryptoSettings []string
	arch           string
	symbols        []binarySymbol

	// unpacked is the reconstruction when this binary was UPX-packed, and nil when it was not. It is
	// carried on the build info because the readers downstream of the scan want it too, since the packed
	// bytes hold no readable version strings either. The caller of scanFile owns it and must Close it.
	unpacked *spillbuf.Buffer
}

// scanFile scans file to try to report the Go and module versions.
func scanFile(ctx context.Context, location file.Location, reader unionreader.UnionReader, captureSymbols bool) ([]*extendedBuildInfo, error) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, errs := unionreader.GetReaders(reader)
	if errs != nil {
		log.WithFields("error", errs).Debug("failed to open a golang binary")
		return nil, fmt.Errorf("failed to open a golang binary: %w", errs)
	}

	var builds []*extendedBuildInfo
	for _, r := range readers {
		build, err := scanReader(ctx, location, r, captureSymbols)
		errs = unknown.Join(errs, err)
		if build != nil {
			builds = append(builds, build)
		}
	}
	return builds, errs
}

// scanReader reports the build info, crypto settings, arch and symbols of a single binary. Everything is
// read from the same reader, which is the unpacked contents when the binary turns out to be UPX-packed:
// the packed bytes carry no readable pclntab or version strings either, so nothing downstream of the
// build info should be looking at them.
func scanReader(ctx context.Context, location file.Location, r io.ReaderAt, captureSymbols bool) (*extendedBuildInfo, error) {
	var errs error

	// unpacked is nil when there was nothing to unpack; readerFor turns that into the reader every parser
	// below should use, so none of them has to ask whether this binary was packed.
	// err can arrive alongside a usable bi: a partial reconstruction still carries build info, and the
	// bytes it lost are a gap worth reporting rather than a reason to drop the binary.
	unpacked, bi, err := readContentsAndBuildInfo(ctx, r)

	// ownership of unpacked transfers to the returned extendedBuildInfo on success. Until then it is held
	// here: the parsers below panic on malformed input (which is why getBuildInfo has a recover), and an
	// unwind past this point would leave a reconstruction of up to maxUPXOriginalSize on disk for the rest
	// of the scan: the temp root is swept, but not until the run ends.
	ownContents := true
	defer func() {
		if ownContents {
			unpacked.Close()
		}
	}()

	if err != nil {
		if isCancelled(err) {
			return nil, err
		}
		log.WithFields("file", location.RealPath, "error", err).Trace("unable to fully read golang buildinfo")
		if reportableGap(err) {
			// the build info is either missing or it is not, and the same err covers both: a partial
			// reconstruction still hands back everything .go.buildinfo carried, and what it lost is the
			// non-loadable tail the readers below want. Saying "unable to read golang buildinfo" there
			// describes a failure that did not happen.
			if bi != nil {
				errs = unknown.Appendf(errs, location, "golang binary read incompletely: %w", err)
			} else {
				errs = unknown.Appendf(errs, location, "unable to read golang buildinfo: %w", err)
			}
		}
		if bi == nil {
			return nil, errs
		}
	}

	// it's possible the reader just isn't a go binary, in which case just skip it
	if bi == nil {
		return nil, errs
	}

	// resolved once, here: every parser below reads the same bytes, and the choice of which reader that is
	// belongs at the top rather than repeated at each call site
	contents := readerFor(unpacked, r)

	// everything below reads those contents through a parser that expands ELF sections, and each bounds its own
	// reads: getSymbols opens the file with elfutil.NewFile, getCryptoInformation gates on
	// elfutil.CheckAllSections. getBuildInfo's CheckSectionNameTable is not what makes these safe, since it
	// bounds only the section elf.NewFile expands as it parses.
	v, err := getCryptoInformation(contents)
	if err != nil {
		log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang version info")
		// don't skip this build info.
		// we can still catalog packages, even if we can't get the crypto information
		errs = unknown.Appendf(errs, location, "unable to read golang version info: %w", err)
	}
	v = append(v, getNativeFIPSSettings(bi.Settings)...)
	arch := getGOARCH(bi.Settings)
	if arch == "" {
		arch, err = getGOARCHFromBin(contents)
		if err != nil {
			log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang arch info")
			// don't skip this build info.
			// we can still catalog packages, even if we can't get the arch information
			errs = unknown.Appendf(errs, location, "unable to read golang arch info: %w", err)
		}
	}

	var symbols []binarySymbol
	if captureSymbols {
		symbols, err = getSymbols(contents)
		if err != nil {
			log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang symbol info")
			// don't skip this build info.
			// we can still catalog packages, even if we can't get the symbol information
			errs = unknown.Appendf(errs, location, "unable to read golang symbol info: %w", err)
		}
	}

	ownContents = false
	return &extendedBuildInfo{BuildInfo: bi, cryptoSettings: v, arch: arch, symbols: symbols, unpacked: unpacked}, errs
}

// reportableGap reports whether err is a gap this cataloger chose to leave, rather than a file it was
// never going to catalog. A packed file we failed to decode, a reconstruction that came up short, and a
// file we declined to expand (from either the ELF section bound or the UPX header bounds) all cost the
// SBOM something real. This cataloger runs on every executable in an image, so reporting anything else
// would attach an unknown to every corrupt, truncated or non-Go binary in it, which is the noise the
// quiet-by-default policy in upx.go exists to avoid.
//
// One real gap is deliberately left off this list: a UPX method we have not implemented. It is the same
// cost to the SBOM as a decode failure, but it fires on most packed binaries rather than on rare ones.
// See errUPXDecompress in upx.go for the reasoning.
func reportableGap(err error) bool {
	return errors.Is(err, errUPXDecompress) ||
		errors.Is(err, errUPXSizeRefused) ||
		errors.Is(err, errUPXPartial) ||
		errors.Is(err, elfutil.ErrDeclaredSizeExceeded)
}

func getCryptoInformation(reader io.ReaderAt) ([]string, error) {
	// goversion opens the file with debug/elf itself and reads .symtab plus the string table it links.
	// Those are expanded lazily, so the section-name table bound getBuildInfo already applied does not
	// reach them: without this gate a 260KB ELF declaring a compressed .symtab drove 1.3GB of allocation.
	if err := elfutil.CheckAllSections(reader); err != nil {
		return nil, err
	}

	v, err := version.ReadExeFromReader(reader)
	if err != nil {
		return nil, err
	}

	return getCryptoSettingsFromVersion(v), nil
}

func getCryptoSettingsFromVersion(v version.Version) []string {
	cryptoSettings := []string{}
	if v.StandardCrypto {
		cryptoSettings = append(cryptoSettings, "standard-crypto")
	}
	if v.BoringCrypto {
		cryptoSettings = append(cryptoSettings, "boring-crypto")
	}
	if v.FIPSOnly {
		cryptoSettings = append(cryptoSettings, "crypto/tls/fipsonly")
	}
	return cryptoSettings
}

func getNativeFIPSSettings(settings []debug.BuildSetting) []string {
	var cryptoSettings []string
	for _, s := range settings {
		switch s.Key {
		case "GOFIPS140":
			if s.Value != "" {
				cryptoSettings = append(cryptoSettings, "GOFIPS140="+s.Value)
			}
		case "DefaultGODEBUG":
			for _, kv := range strings.Split(s.Value, ",") {
				if setting, val, ok := strings.Cut(kv, "="); ok && setting == "fips140" {
					cryptoSettings = append(cryptoSettings, "GODEBUG=fips140="+val)
				}
			}
		}
	}
	return cryptoSettings
}

// readContentsAndBuildInfo returns the contents this binary should be read from, along with its build
// info. A UPX-packed binary is unpacked first and read from the reconstruction.
//
// If the reconstruction carries no build info, the bytes as they were found are tried before giving up.
// The "UPX!" magic is located by an unanchored scan over the first 8KB and every field behind it is
// attacker-controlled, so an ordinary Go binary carrying those four bytes can be made to produce a
// plausible header and a reconstruction of nothing. Without the retry that binary reports no packages at
// all, which turns a false positive here into a way to hide a dependency list.
//
// A gap in the unpack is returned even when build info came through, so it is reported rather than papered
// over: the readers after this one (crypto settings, arch, symbols) read the same contents, and the bytes
// a partial reconstruction lost are exactly the non-loadable tail those depend on. That only holds when
// the contents are a reconstruction: a gap read off the bytes as they were found is not a gap at all, and
// both places below that hand those bytes back drop it.
func readContentsAndBuildInfo(ctx context.Context, r io.ReaderAt) (*spillbuf.Buffer, *debug.BuildInfo, error) {
	unpacked, unpackErr := unpackUPX(ctx, r)
	if isCancelled(unpackErr) {
		return unpacked, nil, unpackErr
	}

	bi, err := getBuildInfo(readerFor(unpacked, r))
	if err == nil && bi != nil {
		if unpacked == nil {
			// nothing was rebuilt, so nothing downstream is short: every reader below this one reads the
			// same bytes getBuildInfo just read in full. unpackUPX returns the input as it was found
			// alongside a refusal (the size bounds) or a failure (block 1 not decoding, or no temp dir),
			// and readable build info in those bytes is itself the evidence the file was not really
			// packed. A genuinely packed binary carries no readable .go.buildinfo in its packed bytes, so
			// it never reaches here and its gap is still reported below.
			return unpacked, bi, nil
		}
		return unpacked, bi, unpackErr
	}

	if unpacked != nil {
		if foundBI, foundErr := getBuildInfo(r); foundErr == nil && foundBI != nil {
			log.WithFields("error", err, "unpackError", unpackErr).
				Trace("UPX reconstruction carried no build info, reading the binary as it was found")
			_ = unpacked.Close()
			// unpackErr is deliberately dropped. Every reader after this one reads the bytes as they were
			// found, not the reconstruction, so nothing downstream is short: the header this binary
			// carried was not describing real UPX output in the first place. Returning the gap here would
			// put an unknown on a binary the cataloger read completely.
			return nil, foundBI, nil
		}
	}

	// a packed file we could not unpack is the more specific gap, so it wins over whatever buildinfo made
	// of the bytes it was handed
	if unpackErr != nil {
		return unpacked, nil, unpackErr
	}
	return unpacked, bi, err
}

// isCancelled reports whether err means the scan was called off, which is a reason to stop rather than a
// gap in the SBOM.
func isCancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// readerFor returns where a scanned binary should be read from: the reconstruction when it was packed,
// the input as it was found otherwise.
//
// The nil check lives here, in one place, on purpose. A nil *spillbuf.Buffer widened into an io.ReaderAt
// is a non-nil interface holding a nil pointer, so it reads as present everywhere it is checked and then
// panics on first use. Every reader below the scan goes through here, so the widening happens once.
func readerFor(unpacked *spillbuf.Buffer, found io.ReaderAt) io.ReaderAt {
	if unpacked == nil {
		return found
	}
	return unpacked
}

// seekerFor is readerFor for the readers after the scan, which seek. found belongs to the caller and is
// reused for every later module, so this deliberately hands back no Closer.
func seekerFor(unpacked *spillbuf.Buffer, found io.ReadSeeker) io.ReadSeeker {
	if unpacked == nil {
		return found
	}
	// the SectionReader snapshots Size() here, which is correct: the reconstruction is complete by the time
	// anything seeks it.
	return io.NewSectionReader(unpacked, 0, unpacked.Size())
}

// readBuildInfo bounds the reader before handing it to debug/buildinfo, which opens ELF files with
// debug/elf itself rather than through elfutil. elf.NewFile expands the section-name string table as it
// parses, so an unbounded read here is reachable no matter how little of the file buildinfo goes on to
// look at.
func readBuildInfo(r io.ReaderAt) (*debug.BuildInfo, error) {
	if err := elfutil.CheckSectionNameTable(r); err != nil {
		return nil, err
	}
	return buildinfo.Read(r)
}

func getBuildInfo(r io.ReaderAt) (bi *debug.BuildInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line. This is the case with :
			// https://github.com/llvm/llvm-project/blob/llvmorg-15.0.6/llvm/test/Object/Inputs/macho-invalid-dysymtab-bad-size
			err = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	bi, err = readBuildInfo(r)

	// note: the stdlib does not export the error we need to check for
	if err != nil {
		if err.Error() == "not a Go executable" {
			// since the cataloger can only select executables and not distinguish if they are a go-compiled
			// binary, we should not show warnings/logs in this case. For this reason we nil-out err here.
			err = nil
			return bi, err
		}
		// in this case we could not read the or parse the file, but not explicitly because it is not a
		// go-compiled binary (though it still might be).
		return bi, err
	}
	return bi, err
}
