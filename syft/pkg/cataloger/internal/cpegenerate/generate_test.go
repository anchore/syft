package cpegenerate

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func keyValues(m map[string]string) []pkg.KeyValue {
	var kvs []pkg.KeyValue
	for k, v := range m {
		kvs = append(kvs, pkg.KeyValue{
			Key:   k,
			Value: v,
		})
	}
	return kvs
}

func TestGeneratePackageCPEs(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "hyphen replacement",
			p: pkg.Package{
				Name:     "name-part",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:python_name_part:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "python language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
				Metadata: pkg.PythonPackage{
					Author:      "alex goodman",
					AuthorEmail: "william.goodman@anchore.com",
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william-goodman:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william-goodman:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william-goodman:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman_project:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman_project:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodman_project:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodmanproject:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodmanproject:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:alex_goodmanproject:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman_project:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman_project:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodman_project:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodmanproject:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodmanproject:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:william_goodmanproject:python_name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "javascript language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Author: "jon",
					URL:    "https://github.com/bob/npm-name",
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:bob:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "ruby language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Ruby,
				Type:     pkg.DebPkg,
				Metadata: pkg.RubyGemspec{
					Authors: []string{
						"someones name",
						"someones.elses.name@gmail.com",
					},
					Homepage: "https://github.com/tom/ruby-name",
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-lang:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:someones-elses-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:someones-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:someones_elses_name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:someones_name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:tom:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "java language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "java language with groupID",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:nexus:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:nexus:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:sonatype:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.sonatype.nexus:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.sonatype.nexus:nexus:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "java with URL in metadata", // regression: https://github.com/anchore/grype/issues/417
			p: pkg.Package{
				Name:    "wstx-asl",
				Version: "3.2.7",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: keyValues(map[string]string{
							"Ant-Version":            "Apache Ant 1.6.5",
							"Built-By":               "tatu",
							"Created-By":             "1.4.2_03-b02 (Sun Microsystems Inc.)",
							"Implementation-Title":   "WoodSToX XML-processor",
							"Implementation-Vendor":  "woodstox.codehaus.org",
							"Implementation-Version": "3.2.7",
							"Manifest-Version":       "1.0",
							"Specification-Title":    "StAX 1.0 API",
							"Specification-Vendor":   "http://jcp.org/en/jsr/detail?id=173",
							"Specification-Version":  "1.0",
						}),
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:woodstox_codehaus_org:wstx-asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:woodstox_codehaus_org:wstx_asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:woodstox-codehaus-org:wstx_asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:woodstox-codehaus-org:wstx-asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx_asl:wstx-asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx-asl:wstx-asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx-asl:wstx_asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx_asl:wstx_asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx:wstx_asl:3.2.7:*:*:*:*:*:*:*",
				"cpe:2.3:a:wstx:wstx-asl:3.2.7:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins package identified via pkg type",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "java language - multi tier manifest fields",
			p: pkg.Package{
				Name:     "cxf-rt-bindings-xml",
				Version:  "3.3.10",
				FoundBy:  "java-cataloger",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "/opt/jboss/keycloak/modules/system/layers/base/org/apache/cxf/impl/main/cxf-rt-bindings-xml-3.3.10.jar",
					Manifest: &pkg.JavaManifest{
						Main: keyValues(map[string]string{
							"Automatic-Module-Name":    "org.apache.cxf.binding.xml",
							"Bnd-LastModified":         "1615836524860",
							"Build-Jdk":                "1.8.0_261",
							"Built-By":                 "dkulp",
							"Bundle-ActivationPolicy":  "lazy",
							"Bundle-Description":       "Apache CXF Runtime XML Binding",
							"Bundle-DocURL":            "http://cxf.apache.org",
							"Bundle-License":           "https://www.apache.org/licenses/LICENSE-2.0.txt",
							"Bundle-ManifestVersion":   "2",
							"Bundle-Name":              "Apache CXF Runtime XML Binding",
							"Bundle-SymbolicName":      "org.apache.cxf.cxf-rt-bindings-xml",
							"Bundle-Vendor":            "The Apache Software Foundation",
							"Bundle-Version":           "3.3.10",
							"Created-By":               "Apache Maven Bundle Plugin",
							"Export-Package":           "org.apache.cxf.binding.xml;version=\"3.3.10\",org.apache.cxf.binding.xml.wsdl11;version=\"3.3.10\",org.apache.cxf.binding.xml.interceptor;version=\"3.3.10\",org.apache.cxf.bindings.xformat;version=\"3.3.10\"",
							"Implementation-Vendor":    "The Apache Software Foundation",
							"Implementation-Vendor-Id": "org.apache",
							"Implementation-Version":   "3.3.10",
							"Import-Package":           "javax.xml.bind;version=\"[0,3)\",javax.xml.bind.annotation;version=\"[0,3)\",javax.wsdl;resolution:=optional,javax.wsdl.extensions;resolution:=optional,javax.wsdl.extensions.http;resolution:=optional,javax.xml.namespace,javax.xml.stream,org.apache.cxf;version=\"[3.3,4)\",org.apache.cxf.binding;version=\"[3.3,4)\",org.apache.cxf.binding.xml,org.apache.cxf.binding.xml.interceptor,org.apache.cxf.bindings.xformat,org.apache.cxf.common.i18n;version=\"[3.3,4)\",org.apache.cxf.common.injection;version=\"[3.3,4)\",org.apache.cxf.common.logging;version=\"[3.3,4)\",org.apache.cxf.common.util;version=\"[3.3,4)\",org.apache.cxf.endpoint;version=\"[3.3,4)\",org.apache.cxf.helpers;version=\"[3.3,4)\",org.apache.cxf.interceptor;version=\"[3.3,4)\",org.apache.cxf.message;version=\"[3.3,4)\",org.apache.cxf.service.model;version=\"[3.3,4)\",org.apache.cxf.staxutils;version=\"[3.3,4)\",org.apache.cxf.tools.common;version=\"[3.3,4)\";resolution:=optional,org.apache.cxf.tools.validator;version=\"[3.3,4)\";resolution:=optional,org.apache.cxf.transport;version=\"[3.3,4)\",org.apache.cxf.wsdl;version=\"[3.3,4)\";resolution:=optional,org.apache.cxf.wsdl.http;version=\"[3.3,4)\",org.apache.cxf.wsdl.interceptors;version=\"[3.3,4)\";resolution:=optional,org.w3c.dom",
							"Manifest-Version":         "1.0",
							"Require-Capability":       "osgi.ee;filter:=\"(&(osgi.ee=JavaSE)(version=1.8))\"",
							"Specification-Vendor":     "The Apache Software Foundation",
							"Specification-Version":    "3.3.10",
							"Tool":                     "Bnd-4.2.0.201903051501",
						}),
					},
					PomProperties: &pkg.JavaPomProperties{
						Path:       "META-INF/maven/org.apache.cxf/cxf-rt-bindings-xml/pom.properties",
						GroupID:    "org.apache.cxf",
						ArtifactID: "cxf-rt-bindings-xml",
						Version:    "3.3.10",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:apache:cxf-rt-bindings-xml:3.3.10:*:*:*:*:*:*:*",
				"cpe:2.3:a:apache:cxf:3.3.10:*:*:*:*:*:*:*",
				"cpe:2.3:a:apache:cxf_rt_bindings_xml:3.3.10:*:*:*:*:*:*:*",
			},
		},
		{
			name: "rpm vendor selection",
			p: pkg.Package{
				Name:    "name",
				Version: "3.2",
				FoundBy: "some-analyzer",
				Type:    pkg.RpmPkg,
				Metadata: pkg.RpmDBEntry{
					Vendor: "some-vendor",
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:some-vendor:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:some_vendor:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "rpm with epoch",
			p: pkg.Package{
				Name:    "name",
				Version: "1:3.2",
				FoundBy: "some-analyzer",
				Type:    pkg.RpmPkg,
				Metadata: pkg.RpmDBEntry{
					Vendor: "some-vendor",
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:1\\:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:some-vendor:name:1\\:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:some_vendor:name:1\\:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "deb with epoch",
			p: pkg.Package{
				Name:     "name",
				Version:  "1:3.2",
				FoundBy:  "some-analyzer",
				Type:     pkg.DebPkg,
				Metadata: pkg.DpkgDBEntry{},
			},
			expected: []string{
				"cpe:2.3:a:name:name:1\\:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "cloudbees jenkins package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "com.cloudbees.jenkins.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.cloudbees.jenkins.plugins:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins.io package identified via groupId prefix",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "io.jenkins.plugins.name.something",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:something:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:something:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:io.jenkins.plugins.name.something:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:io.jenkins.plugins.name.something:something:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins.io package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "io.jenkins.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:io.jenkins.plugins:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins-ci.io package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "io.jenkins-ci.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins-ci:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins_ci:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:io.jenkins-ci.plugins:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins-ci.org package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "org.jenkins-ci.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins-ci:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins_ci:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.jenkins-ci.plugins:name:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jira-atlassian filtering",
			p: pkg.Package{
				Name:     "jira_client_core",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.atlassian.jira",
						ArtifactID: "jira_client_core",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:atlassian:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.atlassian.jira:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.atlassian.jira:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.atlassian.jira:jira-client-core:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "jenkins filtering",
			p: pkg.Package{
				Name:     "cloudbees-installation-manager",
				Version:  "2.89.0.33",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "com.cloudbees.jenkins.modules",
						ArtifactID: "cloudbees-installation-manager",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:modules:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:modules:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.cloudbees.jenkins.modules:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.cloudbees.jenkins.modules:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
			},
		},
		{
			name: "go product and vendor candidates are wired up",
			p: pkg.Package{
				Name:     "github.com/someone/something",
				Version:  "3.2",
				FoundBy:  "go-cataloger",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
			},
			expected: []string{
				"cpe:2.3:a:someone:something:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "go product with vendor candidates and an extra sub-item",
			p: pkg.Package{
				Name:     "github.com/someone/something/more",
				Version:  "3.2",
				FoundBy:  "go-cataloger",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
			},
			expected: []string{
				"cpe:2.3:a:someone:something\\/more:3.2:*:*:*:*:*:*:*",
			},
		},
		{
			name: "generate no CPEs for indeterminate golang package name",
			p: pkg.Package{
				Name:     "github.com/what",
				Version:  "3.2",
				FoundBy:  "go-cataloger",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
			},
			expected: []string{},
		},
		{
			name: "regression: handlebars within java archive",
			p: pkg.Package{
				Name:     "handlebars",
				Version:  "3.0.8",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				FoundBy:  "java-cataloger",
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: keyValues(map[string]string{
							"Extension-Name":         "handlebars",
							"Group-Id":               "org.jenkins-ci.ui",
							"Hudson-Version":         "2.204",
							"Implementation-Title":   "handlebars",
							"Implementation-Version": "3.0.8",
							"Plugin-Version":         "3.0.8",
							"Short-Name":             "handlebars",
						}),
					},
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.jenkins-ci.ui",
						ArtifactID: "handlebars",
						Version:    "3.0.8",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:handlebars:handlebars:3.0.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:handlebarsjs:handlebars:3.0.8:*:*:*:*:*:*:*", // important!
				"cpe:2.3:a:jenkins-ci:handlebars:3.0.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:handlebars:3.0.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins_ci:handlebars:3.0.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:ui:handlebars:3.0.8:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.jenkins-ci.ui:handlebars:3.0.8:*:*:*:*:*:*:*",
			},
		},
		{
			name: "regression: jenkins plugin active-directory",
			p: pkg.Package{
				Name:     "active-directory",
				Version:  "2.25.1",
				Type:     pkg.JenkinsPluginPkg,
				FoundBy:  "java-cataloger",
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: keyValues(map[string]string{
							"Extension-Name": "active-directory",
							"Group-Id":       "org.jenkins-ci.plugins",
						}),
					},
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.jenkins-ci.plugins",
						ArtifactID: "org.jenkins-ci.plugins",
						Version:    "2.25.1",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:active-directory:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:active-directory:active_directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:active:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:active:active_directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:active_directory:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:active_directory:active_directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins-ci:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins-ci:active_directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:active-directory:2.25.1:*:*:*:*:*:*:*", // important!
				"cpe:2.3:a:jenkins:active_directory:2.25.1:*:*:*:*:*:*:*", // important!
				"cpe:2.3:a:jenkins_ci:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins_ci:active_directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.jenkins-ci.plugins:active-directory:2.25.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:org.jenkins-ci.plugins:active_directory:2.25.1:*:*:*:*:*:*:*",
			},
		},
		{
			name: "regression: special characters in CPE should result in no generation",
			p: pkg.Package{
				Name:     "bundler",
				Version:  "2.1.4",
				Type:     pkg.GemPkg,
				FoundBy:  "gem-cataloger",
				Language: pkg.Ruby,
				Metadata: pkg.RubyGemspec{
					Name:    "bundler",
					Version: "2.1.4",
					Authors: []string{
						"jessica lynn suttles",
						"stephanie morillo",
						"david rodríguez",
						"andré medeiros",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:bundler:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-lang:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:jessica-lynn-suttles:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:jessica_lynn_suttles:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:stephanie-morillo:bundler:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:stephanie_morillo:bundler:2.1.4:*:*:*:*:*:*:*",
			},
		},
		{
			name: "regression: python redis shadows normal redis",
			p: pkg.Package{
				Name:     "redis",
				Version:  "2.1.4",
				Type:     pkg.PythonPkg,
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
			},
			expected: []string{
				"cpe:2.3:a:python-redis:python-redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-redis:python_redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-redis:redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python-redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python_redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_redis:python-redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_redis:python_redis:2.1.4:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_redis:redis:2.1.4:*:*:*:*:*:*:*",
			},
		},
		{
			name: "regression: ruby-rake apk missing expected ruby-lang:rake CPE",
			p: pkg.Package{
				Name:     "ruby-rake",
				Version:  "2.7.6-r0",
				Type:     pkg.ApkPkg,
				FoundBy:  "apk-db-analyzer",
				Language: pkg.UnknownLanguage,
				Metadata: pkg.ApkDBEntry{
					Package:       "ruby-rake",
					URL:           "https://www.ruby-lang.org/",
					OriginPackage: "ruby",
				},
			},
			expected: []string{
				"cpe:2.3:a:ruby-lang:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:rake:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:rake:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:rake:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-lang:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-lang:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-rake:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-rake:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-rake:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_rake:rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_rake:ruby-rake:2.7.6-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_rake:ruby_rake:2.7.6-r0:*:*:*:*:*:*:*",
			},
		},
		{
			name: "wordpress plugin",
			p: pkg.Package{
				Name:    "WP Coder",
				Version: "2.5.1",
				Type:    pkg.WordpressPluginPkg,
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "wp-coder",
					Author:                 "Wow-Company",
					AuthorURI:              "https://wow-estore.com",
				},
			},
			expected: []string{
				"cpe:2.3:a:wow-company:wp-coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow-company:wp_coder:2.5.1:*:*:*:*:wordpress:*:*", // this is the correct CPE relative to CVE-2021-25053
				"cpe:2.3:a:wow-estore:wp-coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow-estore:wp_coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow:wp-coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow:wp_coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow_company:wp-coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow_company:wp_coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow_estore:wp-coder:2.5.1:*:*:*:*:wordpress:*:*",
				"cpe:2.3:a:wow_estore:wp_coder:2.5.1:*:*:*:*:wordpress:*:*",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := FromPackageAttributes(test.p)
			expectedCpeSet := set.NewStringSet()
			for _, cpeStr := range test.expected {
				expectedCpeSet.Add("syft-generated:" + cpeStr)
			}

			actualCpeSet := set.NewStringSet()
			for _, a := range actual {
				actualCpeSet.Add(fmt.Sprintf("%s:%s", a.Source.String(), a.Attributes.String()))
			}

			extra := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(extra)
			if len(extra) > 0 {
				t.Errorf("found extra CPEs:")
				for _, d := range extra {
					t.Logf("   %q,\n", d)
				}
			}

			missing := strset.Difference(expectedCpeSet, actualCpeSet).List()
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("missing CPEs:")
				for _, d := range missing {
					t.Logf("   %q,\n", d)
				}
			}
		})
	}
}

func TestCandidateProducts(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "apache-cassandra",
			p: pkg.Package{
				Name: "apache-cassandra",
				Type: pkg.JavaPkg,
			},
			expected: []string{"cassandra" /* <-- known good names | default guess --> */, "apache-cassandra", "apache_cassandra"},
		},
		{
			name: "springframework",
			p: pkg.Package{
				Name: "springframework",
				Type: pkg.JavaPkg,
			},
			expected: []string{"spring_framework", "springsource_spring_framework" /* <-- known good names | default guess --> */, "springframework"},
		},
		{
			name: "spring-security-core",
			p: pkg.Package{
				Name: "spring-security-core",
				Type: pkg.JavaPkg,
			},
			expected: []string{"spring-security-core", "spring_security", "spring_security_core"},
		},
		{
			name: "java",
			p: pkg.Package{
				Name:     "some-java-package-with-group-id",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "com.apple.itunes",
					},
				},
			},
			expected: []string{"itunes", "some-java-package-with-group-id", "some_java_package_with_group_id"},
		},
		{
			name: "java-with-asterisk",
			p: pkg.Package{
				Name:     "some-java-package-with-group-id",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "com.apple.itunes.*",
					},
				},
			},
			expected: []string{"itunes", "some-java-package-with-group-id", "some_java_package_with_group_id"},
		},
		{
			name: "jenkins-plugin",
			p: pkg.Package{
				Name:     "some-jenkins-plugin",
				Type:     pkg.JenkinsPluginPkg,
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "com.cloudbees.jenkins.plugins",
					},
				},
			},
			expected: []string{"some-jenkins-plugin", "some_jenkins_plugin", "jenkins"},
		},
		{
			name: "javascript",
			p: pkg.Package{
				Name: "handlebars.js",
				Type: pkg.NpmPkg,
			},
			expected: []string{"handlebars" /* <-- known good names | default guess --> */, "handlebars.js"},
		},
		{
			name: "gem",
			p: pkg.Package{
				Name: "RedCloth",
				Type: pkg.GemPkg,
			},
			expected: []string{"redcloth_library" /* <-- known good names | default guess --> */, "RedCloth"},
		},
		{
			name: "python",
			p: pkg.Package{
				Name: "python-rrdtool",
				Type: pkg.PythonPkg,
			},
			expected: []string{"rrdtool" /* <-- known good names | default guess --> */, "python-rrdtool", "python_rrdtool"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateProducts(test.p))
		})
	}
}

func TestCandidateVendor(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "elasticsearch",
			p: pkg.Package{
				Name: "elasticsearch",
				Type: pkg.JavaPkg,
			},
			expected: []string{"elastic" /* <-- known good names | default guess --> */, "elasticsearch"},
		},
		{
			name: "spring-security",
			p: pkg.Package{
				Name: "spring-security-core",
				Type: pkg.JavaPkg,
			},
			expected: []string{"vmware" /* <-- known good names | default guess --> */, "spring", "spring-security", "spring-security-core", "spring_security_core", "spring_security"},
		},
		{
			name: "log4j",
			p: pkg.Package{
				Name: "log4j",
				Type: pkg.JavaPkg,
			},
			expected: []string{"apache"},
		},
		{
			name: "Django",
			p: pkg.Package{
				Name: "Django",
				Type: pkg.PythonPkg,
			},
			expected: []string{"djangoproject" /* <-- known good names | default guess --> */, "Django"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v %+v", test.p, test.expected), func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateVendors(test.p))
		})
	}
}

func Test_generateSubSelections(t *testing.T) {
	tests := []struct {
		field    string
		expected []string
	}{
		{
			field:    "jenkins",
			expected: []string{"jenkins"},
		},
		{
			field:    "jenkins-ci",
			expected: []string{"jenkins", "jenkins-ci"},
		},
		{
			field:    "jenkins--ci",
			expected: []string{"jenkins", "jenkins-ci"},
		},
		{
			field:    "jenkins_ci_tools",
			expected: []string{"jenkins", "jenkins_ci", "jenkins_ci_tools"},
		},
		{
			field:    "-jenkins",
			expected: []string{"jenkins"},
		},
		{
			field:    "jenkins_",
			expected: []string{"jenkins"},
		},
		{
			field:    "",
			expected: nil,
		},
		{
			field:    "-",
			expected: nil,
		},
		{
			field:    "_",
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, generateSubSelections(test.field))
		})
	}
}

func Test_addSeparatorVariations(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{
			input:    []string{"jenkins-ci"},
			expected: []string{"jenkins-ci", "jenkins_ci"}, //, "jenkinsci"},
		},
		{
			input:    []string{"jenkins_ci"},
			expected: []string{"jenkins_ci", "jenkins-ci"}, //, "jenkinsci"},
		},
		{
			input:    []string{"jenkins"},
			expected: []string{"jenkins"},
		},
		{
			input:    []string{"jenkins-ci", "circle-ci"},
			expected: []string{"jenkins-ci", "jenkins_ci", "circle-ci", "circle_ci"}, //, "jenkinsci", "circleci"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.input, ","), func(t *testing.T) {
			val := newFieldCandidateSet(test.input...)
			addDelimiterVariations(val)
			assert.ElementsMatch(t, test.expected, val.values())
		})
	}
}

func TestDictionaryFindIsWired(t *testing.T) {

	tests := []struct {
		name       string
		pkg        pkg.Package
		want       []cpe.CPE
		wantExists bool
	}{
		{
			name: "sanity check that cpe data is wired up",
			pkg: pkg.Package{
				Name:    "openssl",
				Version: "1.0.2k",
				Type:    pkg.GemPkg,
			},
			want: []cpe.CPE{
				cpe.Must("cpe:2.3:a:ruby-lang:openssl:1.0.2k:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:ruby-lang:openssl:1.0.2k:*:*:*:*:ruby:*:*", cpe.NVDDictionaryLookupSource),
			},
			// without the cpe data wired up, this would be empty (generation also creates cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*)
			wantExists: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotExists := FromDictionaryFind(tt.pkg)
			assert.ElementsMatch(t, tt.want, got)
			assert.Equal(t, tt.wantExists, gotExists)
		})
	}
}
