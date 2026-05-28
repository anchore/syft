package main

import (
	"github.com/anchore/syft/syft/cpe"
)

// this is a hack to get some information in the output that is otherwise difficult to extract.
// it should be removed after we figure out how to extract it properly from the classifiers
type binaryClassifierOverride struct {
	Class   string
	Package string
	PURL    string
	CPEs    []cpe.CPE
}

var binaryClassifierOverrides = map[string][]binaryClassifierOverride{
	"java-binary": {
		{
			Class:   "java-binary-graalvm",
			Package: "graalvm",
			PURL:    mustPURL("pkg:generic/oracle/graalvm@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-openjdk-zulu",
			Package: "zulu",
			PURL:    mustPURL("pkg:generic/azul/zulu@version"),
			CPEs:    singleCPE("cpe:2.3:a:azul:zulu:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-openjdk-with-update",
			Package: "openjdk",
			PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:{{.primary}}:update{{.update}}:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-openjdk",
			Package: "openjdk",
			PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-ibm",
			Package: "java",
			PURL:    mustPURL("pkg:generic/ibm/java@version"),
			CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-openjdk-fallthrough",
			Package: "jre",
			PURL:    mustPURL("pkg:generic/oracle/jre@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-oracle",
			Package: "jre",
			PURL:    mustPURL("pkg:generic/oracle/jre@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
	},
	"java-jdb-binary": {
		{
			Class:   "java-binary-graalvm",
			Package: "graalvm",
			PURL:    mustPURL("pkg:generic/oracle/graalvm@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm_for_jdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "jdb-binary-openjdk-zulu",
			Package: "zulu",
			PURL:    mustPURL("pkg:generic/azul/zulu@version"),
			CPEs:    singleCPE("cpe:2.3:a:azul:zulu:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-jdb-binary-openjdk",
			Package: "openjdk",
			PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-sdk-binary-ibm",
			Package: "java_sdk",
			PURL:    mustPURL("pkg:generic/ibm/java_sdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:ibm:java_sdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-openjdk-fallthrough",
			Package: "openjdk",
			PURL:    mustPURL("pkg:generic/oracle/openjdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "java-binary-jdk",
			Package: "jdk",
			PURL:    mustPURL("pkg:generic/oracle/jdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
	},
	"openssl-binary": {
		{
			Class:   "openssl-binary-aws-lc",
			Package: "aws-lc",
			PURL:    mustPURL("pkg:generic/aws-lc@version"),
			CPEs:    singleCPE("cpe:2.3:a:amazon:aws_libcrypto:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:   "openssl-binary",
			Package: "openssl",
			PURL:    mustPURL("pkg:generic/openssl@version"),
			CPEs:    singleCPE("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
	},
	"mysqld-binary": {
		{
			Class:   "mysqld-mysql-cluster-legacy-binary",
			Package: "mysql-cluster",
			PURL:    mustPURL("pkg:generic/mysql-cluster@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql_cluster:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:   "mysqld-mysql-cluster-binary",
			Package: "mysql-cluster",
			PURL:    mustPURL("pkg:generic/mysql-cluster@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:oracle:mysql_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:oracle:mysql_cluster:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:   "mysqld-mysql-server-binary",
			Package: "mysql-server",
			PURL:    mustPURL("pkg:generic/mysql-server@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:oracle:mysql_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
	},
}

func mustPURL(purl string) string {
	return purl
}

func singleCPE(cpeString string, source ...cpe.Source) []cpe.CPE {
	src := cpe.GeneratedSource
	if len(source) > 0 {
		src = source[0]
	}
	return []cpe.CPE{
		cpe.Must(cpeString, src),
	}
}
