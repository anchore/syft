package integration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestJavaPURLs(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-test-java-purls", source.SquashedScope, nil)
	found := make(map[string]string)
	for _, p := range sbom.Artifacts.Packages.Sorted() {
		if p.Type != pkg.JavaPkg && p.Type != pkg.JenkinsPluginPkg {
			continue
		}
		key := fmt.Sprintf("%s@%s", p.Name, p.Version)
		found[key] = p.PURL
	}
	for key, expectedPURL := range expectedPURLs {
		purl := found[key]
		assert.Equal(t, expectedPURL, purl, fmt.Sprintf("found wrong or missing PURL for %s want %s, got %s", key, expectedPURL, purl))
	}
	for key, foundPURL := range found {
		expectedPURL := expectedPURLs[key]
		assert.Equal(t, expectedPURL, foundPURL, fmt.Sprintf("found extra purl for %s want %s, got %s", key, expectedPURL, foundPURL))
	}
}

// Constructed by:
// syft anchore/test_images:java-56d52bc -o template -t /tmp/test.templ | grep 'pkg:maven' | sort | uniq >> test/integration/java_purl_test.go
// where the template is:
/*
{{ range .Artifacts}}"{{.Name}}@{{.Version}}":"{{.PURL}}",
{{ end }}
*/
// The map was then hand-edited for correctness by comparing to Maven Central.
var expectedPURLs = map[string]string{
	"TwilioNotifier@0.2.1":                            "pkg:maven/com.twilio.jenkins/TwilioNotifier@0.2.1",
	"access-modifier-annotation@1.0":                  "pkg:maven/org.kohsuke/access-modifier-annotation@1.0",
	"acegi-security@1.0.5":                            "pkg:maven/org.acegisecurity/acegi-security@1.0.5",
	"activation@1.1.1-hudson-1":                       "pkg:maven/org.jvnet.hudson/activation@1.1.1-hudson-1",
	"akuma@1.2":                                       "pkg:maven/com.sun.akuma/akuma@1.2",
	"animal-sniffer-annotation@1.0":                   "pkg:maven/org.jvnet/animal-sniffer-annotation@1.0",
	"annotation-indexer@1.2":                          "pkg:maven/org.jvnet.hudson/annotation-indexer@1.2",
	"annotations@13.0":                                "pkg:maven/org.jetbrains/annotations@13.0",
	"ant-launcher@1.8.0":                              "pkg:maven/org.apache.ant/ant-launcher@1.8.0",
	"ant@1.8.0":                                       "pkg:maven/org.apache.ant/ant@1.8.0",
	"antlr@2.7.6":                                     "pkg:maven/antlr/antlr@2.7.6",
	"aopalliance@1.0":                                 "pkg:maven/aopalliance/aopalliance@1.0",
	"args4j@2.0.16":                                   "pkg:maven/args4j/args4j@2.0.16",
	"asm-commons@2.2.3":                               "pkg:maven/asm-commons/asm-commons@2.2.3",
	"asm-tree@2.2.3":                                  "pkg:maven/asm-tree/asm-tree@2.2.3",
	"asm@2.2.3":                                       "pkg:maven/asm/asm@2.2.3",
	"avalon-framework@4.1.3":                          "pkg:maven/avalon-framework/avalon-framework@4.1.3",
	"bridge-method-annotation@1.2":                    "pkg:maven/com.infradna.tool/bridge-method-annotation@1.2",
	"classworlds@1.1":                                 "pkg:maven/org.codehaus.classworlds/classworlds@1.1",
	"cli@1.390":                                       "pkg:maven/org.jvnet.hudson.main/cli@1.390",
	"commons-beanutils@1.8.0":                         "pkg:maven/commons-beanutils/commons-beanutils@1.8.0",
	"commons-codec@1.2":                               "pkg:maven/commons-codec/commons-codec@1.2",
	"commons-codec@1.4":                               "pkg:maven/commons-codec/commons-codec@1.4",
	"commons-collections@3.2":                         "pkg:maven/commons-collections/commons-collections@3.2",
	"commons-digester@1.7":                            "pkg:maven/commons-digester/commons-digester@1.7",
	"commons-discovery@0.4":                           "pkg:maven/commons-discovery/commons-discovery@0.4",
	"commons-fileupload@1.2.1":                        "pkg:maven/commons-fileupload/commons-fileupload@1.2.1",
	"commons-httpclient@3.1":                          "pkg:maven/org.apache/commons-httpclient@3.1",
	"commons-httpclient@3.1-rc1":                      "pkg:maven/commons-httpclient/commons-httpclient@3.1-rc1",
	"commons-io@1.4":                                  "pkg:maven/commons-io/commons-io@1.4",
	"commons-jelly-tags-define@1.0.1-hudson-20071021": "pkg:maven/org.jvnet.hudson/commons-jelly-tags-define@1.0.1-hudson-20071021",
	"commons-jelly-tags-fmt@1.0":                      "pkg:maven/commons-jelly-tags-fmt/commons-jelly-tags-fmt@1.0",
	"commons-jelly-tags-xml@1.1":                      "pkg:maven/commons-jelly-tags-xml/commons-jelly-tags-xml@1.1",
	"commons-jelly@1.1-hudson-20100305":               "pkg:maven/org.jvnet.hudson/commons-jelly@1.1-hudson-20100305",
	"commons-jexl@1.1-hudson-20090508":                "pkg:maven/org.jvnet.hudson/commons-jexl@1.1-hudson-20090508",
	"commons-lang@2.4":                                "pkg:maven/commons-lang/commons-lang@2.4",
	"commons-lang@2.5":                                "pkg:maven/commons-lang/commons-lang@2.5",
	"commons-logging@1.0.4":                           "pkg:maven/commons-logging/commons-logging@1.0.4", // see https://mvnrepository.com/artifact/commons-logging/commons-logging/1.0.4
	"commons-logging@1.1":                             "pkg:maven/commons-logging/commons-logging@1.1",   // see https://mvnrepository.com/artifact/commons-logging/commons-logging/1.1
	"commons-logging@1.1.1":                           "pkg:maven/commons-logging/commons-logging@1.1.1", // see https://mvnrepository.com/artifact/commons-logging/commons-logging/1.1.1
	"commons-pool@1.3":                                "pkg:maven/commons-pool/commons-pool@1.3",
	"crypto-util@1.0":                                 "pkg:maven/org.jvnet.hudson/crypto-util@1.0",
	"cvs@1.2":                                         "pkg:maven/org.jvnet.hudson.plugins/cvs@1.2",
	"dom4j@1.6.1-hudson-3":                            "pkg:maven/dom4j/dom4j@1.6.1-hudson-3",
	"doxia-sink-api@1.0-alpha-10":                     "pkg:maven/org.apache.maven.doxia/doxia-sink-api@1.0-alpha-10",
	"easymock@2.4":                                    "pkg:maven/org.easymock/easymock@2.4",
	"embedded_su4j@1.1":                               "pkg:maven/com.sun.solaris/embedded_su4j@1.1",
	"example-java-app-gradle@0.1.0":                   "pkg:maven/example-java-app-gradle/example-java-app-gradle@0.1.0",
	"ezmorph@1.0.3":                                   "pkg:maven/net.sf.ezmorph/ezmorph@1.0.3",
	"graph-layouter@1.0":                              "pkg:maven/org.kohsuke/graph-layouter@1.0",
	"groovy-all@1.6.0":                                "pkg:maven/groovy-all/groovy-all@1.6.0",
	"gson@2.8.6":                                      "pkg:maven/com.google.code.gson/gson@2.8.6",
	"guava@r06":                                       "pkg:maven/com.google.guava/guava@r06",
	"httpclient@4.1.1":                                "pkg:maven/org.apache.httpcomponents/httpclient@4.1.1",
	"httpcore@4.1":                                    "pkg:maven/org.apache.httpcomponents/httpcore@4.1",
	"hudson-cli@":                                     "pkg:maven/hudson-cli/hudson-cli",
	"hudson-core@1.390":                               "pkg:maven/org.jvnet.hudson.main/hudson-core@1.390",
	"hudson-war@1.390":                                "pkg:maven/org.jvnet.hudson.main/hudson-war@1.390",
	"j-interop@2.0.5":                                 "pkg:maven/j-interop/j-interop@2.0.5",
	"j-interopdeps@2.0.5":                             "pkg:maven/j-interopdeps/j-interopdeps@2.0.5",
	"jaxen@1.1-beta-11":                               "pkg:maven/org.jaxen/jaxen@1.1-beta-11",
	"jcaptcha-all@1.0-RC6":                            "pkg:maven/jcaptcha-all/jcaptcha-all@1.0-RC6",
	"jcifs@1.3.14-kohsuke-1":                          "pkg:maven/org.samba.jcifs/jcifs@1.3.14-kohsuke-1",
	"jcommon@1.0.12":                                  "pkg:maven/jfree/jcommon@1.0.12",
	"jfreechart@1.0.9":                                "pkg:maven/jfreechart/jfreechart@1.0.9",
	"jinterop-proxy@1.1":                              "pkg:maven/org.kohsuke.jinterop/jinterop-proxy@1.1",
	"jinterop-wmi@1.0":                                "pkg:maven/org.jvnet.hudson/jinterop-wmi@1.0",
	"jline@0.9.94":                                    "pkg:maven/jline/jline@0.9.94",
	"jmdns@3.1.6-hudson-2":                            "pkg:maven/com.strangeberry.jmdns.tools.Main/jmdns@3.1.6-hudson-2",
	"jna-posix@1.0.3":                                 "pkg:maven/org.jruby.ext.posix/jna-posix@1.0.3",
	"jna@3.2.4":                                       "pkg:maven/com.sun.jna/jna@3.2.4",
	"jsch@0.1.27":                                     "pkg:maven/jsch/jsch@0.1.27",
	"json-lib@2.1-rev6":                               "pkg:maven/json-lib/json-lib@2.1-rev6",
	"json@20200518":                                   "pkg:maven/org.json/json@20200518",
	"jstl@1.1.0":                                      "pkg:maven/com.sun/jstl@1.1.0",
	"jtidy@4aug2000r7-dev-hudson-1":                   "pkg:maven/jtidy/jtidy@4aug2000r7-dev-hudson-1",
	"junit@4.13.1":                                    "pkg:maven/junit/junit@4.13.1",
	"kotlin-stdlib-common@1.3.70":                     "pkg:maven/kotlin-stdlib-common/kotlin-stdlib-common@1.3.70",
	"kotlin-stdlib@1.3.70":                            "pkg:maven/kotlin-stdlib/kotlin-stdlib@1.3.70",
	"libpam4j@1.2":                                    "pkg:maven/org.jvnet.libpam4j/libpam4j@1.2",
	"libzfs@0.5":                                      "pkg:maven/org.jvnet.libzfs/libzfs@0.5",
	"localizer@1.10":                                  "pkg:maven/org.jvnet.localizer/localizer@1.10",
	"log4j@1.2.9":                                     "pkg:maven/log4j/log4j@1.2.9",
	"logkit@1.0.1":                                    "pkg:maven/logkit/logkit@1.0.1",
	"mail@1.4":                                        "pkg:maven/com.sun/mail@1.4",
	"maven-agent@1.390":                               "pkg:maven/org.jvnet.hudson.main/maven-agent@1.390",
	"maven-artifact-manager@2.0.9":                    "pkg:maven/org.apache.maven/maven-artifact-manager@2.0.9",
	"maven-artifact@2.0.9":                            "pkg:maven/org.apache.maven/maven-artifact@2.0.9",
	"maven-core@2.0.9":                                "pkg:maven/org.apache.maven/maven-core@2.0.9",
	"maven-embedder@2.0.4":                            "pkg:maven/org.apache.maven/maven-embedder@2.0.4",
	"maven-embedder@2.0.4-hudson-1":                   "pkg:maven/org.jvnet.hudson/maven-embedder@2.0.4-hudson-1",
	"maven-error-diagnostics@2.0.9":                   "pkg:maven/org.apache.maven/maven-error-diagnostics@2.0.9",
	"maven-interceptor@1.390":                         "pkg:maven/org.jvnet.hudson.main/maven-interceptor@1.390",
	"maven-model@2.0.9":                               "pkg:maven/org.apache.maven/maven-model@2.0.9",
	"maven-monitor@2.0.9":                             "pkg:maven/org.apache.maven/maven-monitor@2.0.9",
	"maven-plugin-api@2.0.9":                          "pkg:maven/org.apache.maven/maven-plugin-api@2.0.9",
	"maven-plugin-descriptor@2.0.9":                   "pkg:maven/org.apache.maven/maven-plugin-descriptor@2.0.9",
	"maven-plugin-parameter-documenter@2.0.9":         "pkg:maven/org.apache.maven/maven-plugin-parameter-documenter@2.0.9",
	"maven-plugin-registry@2.0.9":                     "pkg:maven/org.apache.maven/maven-plugin-registry@2.0.9",
	"maven-plugin@1.390":                              "pkg:maven/org.jvnet.hudson.main/maven-plugin@1.390",
	"maven-profile@2.0.9":                             "pkg:maven/org.apache.maven/maven-profile@2.0.9",
	"maven-project@2.0.9":                             "pkg:maven/org.apache.maven/maven-project@2.0.9",
	"maven-reporting-api@2.0.9":                       "pkg:maven/org.apache.maven.reporting/maven-reporting-api@2.0.9",
	"maven-repository-metadata@2.0.9":                 "pkg:maven/org.apache.maven/maven-repository-metadata@2.0.9",
	"maven-settings@2.0.9":                            "pkg:maven/org.apache.maven/maven-settings@2.0.9",
	"maven2.1-interceptor@1.2":                        "pkg:maven/org.jvnet.hudson/maven2.1-interceptor@1.2",
	"memory-monitor@1.3":                              "pkg:maven/org.jvnet.hudson/memory-monitor@1.3",
	"nomad@0.7.4":                                     "pkg:maven/org.jenkins-ci.plugins/nomad@0.7.4",
	"okhttp@4.5.0":                                    "pkg:maven/com.squareup.okhttp3/okhttp@4.5.0",
	"okio@2.5.0":                                      "pkg:maven/com.squareup.okio/okio@2.5.0",
	"oro@2.0.8":                                       "pkg:maven/org.apache.oro/oro@2.0.8",
	"plexus-container-default@1.0-alpha-9-stable-1":   "pkg:maven/org.codehaus.plexus/plexus-container-default@1.0-alpha-9-stable-1",
	"plexus-interactivity-api@1.0-alpha-4":            "pkg:maven/org.codehaus.plexus/plexus-interactivity-api@1.0-alpha-4",
	"plexus-utils@1.5.1":                              "pkg:maven/org.codehaus.plexus/plexus-utils@1.5.1",
	"remoting@1.390":                                  "pkg:maven/org.jvnet.hudson.main/remoting@1.390",
	"robust-http-client@1.1":                          "pkg:maven/org.jvnet.robust-http-client/robust-http-client@1.1",
	"sdk@3.0":                                         "pkg:maven/sdk/sdk@3.0",
	"sezpoz@1.7":                                      "pkg:maven/net.java.sezpoz/sezpoz@1.7",
	"slave@":                                          "pkg:maven/slave/slave",
	"slide-webdavlib@2.1":                             "pkg:maven/slide-webdavlib/slide-webdavlib@2.1",
	"spring-aop@2.5":                                  "pkg:maven/org.springframework.bundle.spring.aop/spring-aop@2.5",
	"spring-beans@2.5":                                "pkg:maven/org.springframework/spring-beans@2.5",
	"spring-context@2.5":                              "pkg:maven/org.springframework.bundle.spring.context/spring-context@2.5",
	"spring-core@2.5":                                 "pkg:maven/org.springframework/spring-core@2.5",
	"spring-dao@1.2.9":                                "pkg:maven/spring-dao/spring-dao@1.2.9",
	"spring-jdbc@1.2.9":                               "pkg:maven/spring-jdbc/spring-jdbc@1.2.9",
	"spring-web@2.5":                                  "pkg:maven/org.springframework/spring-web@2.5",
	"ssh-slaves@0.14":                                 "pkg:maven/org.jvnet.hudson.plugins/ssh-slaves@0.14",
	"stapler-adjunct-timeline@1.2":                    "pkg:maven/org.kohsuke.stapler/stapler-adjunct-timeline@1.2",
	"stapler-jelly@1.155":                             "pkg:maven/org.kohsuke.stapler/stapler-jelly@1.155",
	"stapler@1.155":                                   "pkg:maven/org.kohsuke.stapler/stapler@1.155",
	"stax-api@1.0.1":                                  "pkg:maven/stax-api/stax-api@1.0.1",
	"subversion@1.20":                                 "pkg:maven/org.jvnet.hudson.plugins/subversion@1.20",
	"svnkit@1.3.4-hudson-2":                           "pkg:maven/svnkit/svnkit@1.3.4-hudson-2",
	"task-reactor@1.2":                                "pkg:maven/org.jvnet.hudson/task-reactor@1.2",
	"tiger-types@1.3":                                 "pkg:maven/org.jvnet/tiger-types@1.3",
	"trilead-putty-extension@1.0":                     "pkg:maven/org.kohsuke/trilead-putty-extension@1.0",
	"trilead-ssh2@build212-hudson-5":                  "pkg:maven/org.jvnet.hudson/trilead-ssh2@build212-hudson-5",
	"txw2@20070624":                                   "pkg:maven/txw2/txw2@20070624",
	"wagon-file@1.0-beta-2":                           "pkg:maven/org.apache.maven.wagon/wagon-file@1.0-beta-2",
	"wagon-http-lightweight@1.0-beta-2":               "pkg:maven/org.apache.maven.wagon/wagon-http-lightweight@1.0-beta-2",
	"wagon-http-shared@1.0-beta-2":                    "pkg:maven/org.apache.maven.wagon/wagon-http-shared@1.0-beta-2",
	"wagon-provider-api@1.0-beta-2":                   "pkg:maven/org.apache.maven.wagon/wagon-provider-api@1.0-beta-2",
	"wagon-ssh-common@1.0-beta-2":                     "pkg:maven/org.apache.maven.wagon/wagon-ssh-common@1.0-beta-2",
	"wagon-ssh-external@1.0-beta-2":                   "pkg:maven/org.apache.maven.wagon/wagon-ssh-external@1.0-beta-2",
	"wagon-ssh@1.0-beta-2":                            "pkg:maven/org.apache.maven.wagon/wagon-ssh@1.0-beta-2",
	"wagon-webdav@1.0-beta-2-hudson-1":                "pkg:maven/org.jvnet.hudson/wagon-webdav@1.0-beta-2-hudson-1",
	"windows-remote-command@1.0":                      "pkg:maven/org.jvnet.hudson/windows-remote-command@1.0",
	"winp@1.14":                                       "pkg:maven/org.jvnet.winp/winp@1.14",
	"winstone@0.9.10-hudson-24":                       "pkg:maven/org.jvnet.hudson.winstone/winstone@0.9.10-hudson-24",
	"wstx-asl@3.2.7":                                  "pkg:maven/wstx-asl/wstx-asl@3.2.7",
	"xml-im-exporter@1.1":                             "pkg:maven/xml-im-exporter/xml-im-exporter@1.1",
	"xpp3@1.1.4c":                                     "pkg:maven/xpp3/xpp3@1.1.4c",
	"xpp3_min@1.1.4c":                                 "pkg:maven/xpp3_min/xpp3_min@1.1.4c",
	"xstream@1.3.1-hudson-8":                          "pkg:maven/org.jvnet.hudson/xstream@1.3.1-hudson-8",
}
