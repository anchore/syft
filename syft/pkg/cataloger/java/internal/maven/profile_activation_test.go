package maven

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseSingleProfile(t *testing.T, profileXML string) Profile {
	t.Helper()
	pomXML := `<project xmlns="http://maven.apache.org/POM/4.0.0"><profiles>` + profileXML + `</profiles></project>`
	pom, err := ParsePomXML(strings.NewReader(pomXML))
	require.NoError(t, err)
	profiles := deref(pom.Profiles)
	require.Len(t, profiles, 1)
	return profiles[0]
}

func Test_profileCanBeActive(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		expected bool
	}{
		{
			name: "no activation block",
			profile: `<profile>
				<id>manual</id>
			</profile>`,
			expected: true, // can still be activated with -P
		},
		{
			name: "activeByDefault true",
			profile: `<profile>
				<id>on-by-default</id>
				<activation><activeByDefault>true</activeByDefault></activation>
			</profile>`,
			expected: true,
		},
		{
			name: "activeByDefault false only",
			profile: `<profile>
				<id>explicit-off</id>
				<activation><activeByDefault>false</activeByDefault></activation>
			</profile>`,
			expected: false, // explicitly off unless requested with -P
		},
		{
			name: "activeByDefault false with other activator",
			profile: `<profile>
				<id>explicit-off-with-jdk</id>
				<activation>
					<activeByDefault>false</activeByDefault>
					<jdk>[17,)</jdk>
				</activation>
			</profile>`,
			expected: true, // the jdk activator can still match a build
		},
		{
			name: "jdk satisfiable lower bound",
			profile: `<profile>
				<id>jdk-9-plus</id>
				<activation><jdk>[9,)</jdk></activation>
			</profile>`,
			expected: true,
		},
		{
			name: "jdk open upper bound beyond any released JDK",
			profile: `<profile>
				<id>future-jdk</id>
				<activation><jdk>[99,)</jdk></activation>
			</profile>`,
			expected: true, // satisfied by a high enough JDK, whether or not one has shipped yet
		},
		{
			name: "jdk empty range",
			profile: `<profile>
				<id>empty-range</id>
				<activation><jdk>[17,9)</jdk></activation>
			</profile>`,
			expected: false,
		},
		{
			name: "jdk open range on lower version",
			profile: `<profile>
				<id>jdk-8-plus</id>
				<activation><jdk>1.8</jdk></activation>
			</profile>`,
			expected: true,
		},
		{
			name: "jdk bare version beyond any released JDK",
			profile: `<profile>
				<id>jdk-99-minimum</id>
				<activation><jdk>99</jdk></activation>
			</profile>`,
			expected: true, // a bare version is a minimum, satisfiable by a high enough JDK
		},
		{
			name: "os activator not evaluated",
			profile: `<profile>
				<id>on-windows</id>
				<activation><os><family>windows</family></os></activation>
			</profile>`,
			expected: true,
		},
		{
			name: "property activator not evaluated",
			profile: `<profile>
				<id>on-flag</id>
				<activation><property><name>env.CI</name></property></activation>
			</profile>`,
			expected: true,
		},
		{
			name: "file activator not evaluated",
			profile: `<profile>
				<id>if-file-exists</id>
				<activation><file><exists>Makefile</exists></file></activation>
			</profile>`,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := parseSingleProfile(t, test.profile)
			assert.Equal(t, test.expected, profileCanBeActive(profile))
		})
	}
}

func Test_DirectPomDependencies_skipsInactiveProfiles(t *testing.T) {
	pomXML := `<project xmlns="http://maven.apache.org/POM/4.0.0">
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.example</groupId>
	<artifactId>probe-app</artifactId>
	<version>1.0.0</version>
	<dependencies>
		<dependency>
			<groupId>com.google.guava</groupId>
			<artifactId>guava</artifactId>
			<version>32.1.2-jre</version>
		</dependency>
	</dependencies>
	<profiles>
		<profile>
			<id>future-jdk</id>
			<activation>
				<jdk>[99,)</jdk>
			</activation>
			<dependencies>
				<dependency>
					<groupId>com.example</groupId>
					<artifactId>only-on-jdk99</artifactId>
					<version>9.9.9</version>
				</dependency>
			</dependencies>
		</profile>
		<profile>
			<id>explicit-off</id>
			<activation><activeByDefault>false</activeByDefault></activation>
			<dependencies>
				<dependency>
					<groupId>com.example</groupId>
					<artifactId>off-by-default</artifactId>
					<version>0.0.1</version>
				</dependency>
			</dependencies>
		</profile>
		<profile>
			<id>satisfiable</id>
			<activation><jdk>[9,)</jdk></activation>
			<dependencies>
				<dependency>
					<groupId>com.example</groupId>
					<artifactId>on-modern-jdk</artifactId>
					<version>2.0.0</version>
				</dependency>
			</dependencies>
		</profile>
	</profiles>
</project>`

	pom, err := ParsePomXML(strings.NewReader(pomXML))
	require.NoError(t, err)

	var names []string
	for _, dep := range DirectPomDependencies(pom) {
		names = append(names, deref(dep.ArtifactID))
	}
	assert.ElementsMatch(t, []string{"guava", "on-modern-jdk", "only-on-jdk99"}, names)
}
