package binary

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/binutils"
)

//nolint:funlen
func defaultJavaClassifiers() []binutils.Classifier {
	m := binutils.ContextualEvidenceMatchers{CatalogerName: catalogerName}

	return []binutils.Classifier{
		{
			Class:    "java-binary",
			FileGlob: "**/java",
			EvidenceMatcher: binutils.BranchingEvidenceMatcher([]binutils.Classifier{
				{
					Class: "java-binary-graalvm",
					EvidenceMatcher: m.FileContentsVersionMatcher(
						`(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00`),
					Package: "graalvm",
					PURL:    mustPURL("pkg:generic/oracle/graalvm@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-openjdk-zulu",
					EvidenceMatcher: binutils.MatchAll(
						binutils.MatchPath(`**/*zulu*/**`),
						binutils.MatchAny(
							m.FileContentsVersionMatcher(
								// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
								`(?m)\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
							m.FileContentsVersionMatcher(
								// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]11.0.22+7[NUL][NUL][NUL][NUL][NUL][NUL][NUL]openjdk[NUL]java[NUL]
								`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+(openjdk|java)`),
						),
					),
					Package: "zulu",
					PURL:    mustPURL("pkg:generic/azul/zulu@version"),
					CPEs:    singleCPE("cpe:2.3:a:azul:zulu:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-openjdk-with-update",
					EvidenceMatcher: binutils.MatchAny(
						m.FileContentsVersionMatcher(
							`openjdk`,
							// [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
							`(?m)java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>(?<primary>[0-9]+[^\x00]+)_(?<update>[^\x00]+)-[^\x00]+)\x00`),
						m.FileContentsVersionMatcher(
							`openjdk`,
							// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]1.8.0_352-b08[NUL][NUL][NUL][NUL][NUL][NUL][NUL]openjdk[NUL]java[NUL]
							`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>(?<primary>[0-9]+[^\x00]+)_(?<update>[^\x00]+)-[^\x00]+)\x00+openjdk\x00java`),
					),
					Package: "openjdk",
					PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:{{.primary}}:update{{.update}}:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-openjdk",
					EvidenceMatcher: binutils.MatchAny(
						m.FileContentsVersionMatcher(
							// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
							`(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
						m.FileContentsVersionMatcher(
							// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]11.0.22+7[NUL][NUL][NUL][NUL][NUL][NUL][NUL]openjdk[NUL]java[NUL]
							`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java`),
					),
					Package: "openjdk",
					PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-ibm",
					EvidenceMatcher: binutils.MatchAll(
						binutils.MatchAny(
							binutils.MatchPath("**/ibm/**"),
							binutils.SharedLibraryLookup(
								`^libjli\.so$`,
								m.FileContentsVersionMatcher("IBM_JAVA")),
						),
						m.FileContentsVersionMatcher(
							// [NUL]java[NUL]1.8[NUL][NUL][NUL]1.8.0-foreman_2022_01_20_09_33-b00[NUL]
							`(?m)\x00java\x00+(?P<release>[0-9]+[.0-9]+)\x00+(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
					),
					Package: "java",
					PURL:    mustPURL("pkg:generic/ibm/java@version"),
					CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-openjdk-fallthrough",
					EvidenceMatcher: m.FileContentsVersionMatcher(
						"openjdk",
						// [NUL]19.0.1+10-21[NUL]
						`(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00`,
					),
					Package: "jre",
					PURL:    mustPURL("pkg:generic/oracle/jre@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-oracle",
					EvidenceMatcher: m.FileContentsVersionMatcher(
						// [NUL]19.0.1+10-21[NUL]
						// java[NUL]1.8[NUL]1.8.0_451-b10
						`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[-._+a-zA-Z0-9]+)\x00`,
					),
					Package: "jre",
					PURL:    mustPURL("pkg:generic/oracle/jre@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
			}...),
		},
		{
			Class:    "java-jdb-binary",
			FileGlob: "**/jdb",
			EvidenceMatcher: binutils.BranchingEvidenceMatcher([]binutils.Classifier{
				{
					Class: "java-binary-graalvm",
					EvidenceMatcher: m.FileContentsVersionMatcher(
						`(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00`),
					Package: "graalvm",
					PURL:    mustPURL("pkg:generic/oracle/graalvm@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm_for_jdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "jdb-binary-openjdk-zulu",
					EvidenceMatcher: binutils.MatchAll(
						binutils.MatchPath("**/*zulu*/**"),
						binutils.MatchAny(
							m.FileContentsVersionMatcher(
								// [NUL]jdb[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
								`(?m)(java|jdb)\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
							m.FileContentsVersionMatcher(
								// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]11.0.22+7[NUL][NUL][NUL][NUL][NUL][NUL][NUL]jdb[NUL]
								`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+(java|jdb)`),
						),
					),
					Package: "zulu",
					PURL:    mustPURL("pkg:generic/azul/zulu@version"),
					CPEs:    singleCPE("cpe:2.3:a:azul:zulu:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-jdb-binary-openjdk",
					EvidenceMatcher: binutils.MatchAll(
						m.FileContentsVersionMatcher(
							// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
							// [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
							`(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
						m.FileContentsVersionMatcher(
							// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]11.0.22+7[NUL][NUL][NUL][NUL][NUL][NUL][NUL]openjdk[NUL]java[NUL]
							`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java`),
					),
					Package: "openjdk",
					PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-sdk-binary-ibm",
					EvidenceMatcher: binutils.MatchAll(
						binutils.MatchAny(
							binutils.MatchPath("**/ibm/**"),
							binutils.SharedLibraryLookup(
								`^libjli\.so$`,
								m.FileContentsVersionMatcher("IBM_JAVA")),
						),
						m.FileContentsVersionMatcher(
							// [NUL]java[NUL]./lib/tools.jar./lib/sa-jdi.jar./classes.-J-ms8m[NUL][NUL]1.8[NUL][NUL][NUL]1.8.0-foreman_2022_01_20_09_33-b00[NUL]
							`(?m)\x00java\x00.+?\x00(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
					),
					Package: "java_sdk",
					PURL:    mustPURL("pkg:generic/ibm/java_sdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:ibm:java_sdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-openjdk-fallthrough",
					EvidenceMatcher: binutils.MatchAll(
						m.FileContentsVersionMatcher(
							"openjdk",
							`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00`),
					),
					Package: "openjdk",
					PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
				{
					Class: "java-binary-jdk",
					EvidenceMatcher: m.FileContentsVersionMatcher(
						`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00`),
					Package: "jdk",
					PURL:    mustPURL("pkg:generic/oracle/jdk@version"),
					CPEs:    singleCPE("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				},
			}...),
		},
	}
}
