package maven

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_licensesFromComments(t *testing.T) {
	licenses := ExtractLicensesFromComments(`<?xml version="1.0" encoding="UTF-8"?>
<!--
 Oracle licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License. You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
-->
<project/>`)

	require.Len(t, licenses, 1)
	require.NotNil(t, licenses[0].Name)
	require.Equal(t, "Apache-2.0", *licenses[0].Name)
	require.NotNil(t, licenses[0].URL)
	require.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0", *licenses[0].URL)
}

func Test_licensesFromComments_ignoresNonLicenseURLs(t *testing.T) {
	licenses := ExtractLicensesFromComments(`<?xml version="1.0" encoding="UTF-8"?>
<!-- build note: see https://github.com/example/project/issues/123 -->
<project/>`)

	require.Nil(t, licenses)
}

func TestResolver_ResolveLicenses_prefersStructuredLicensesOverComments(t *testing.T) {
	pom, err := ParsePomXML(strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: MIT -->
<project>
  <modelVersion>4.0.0</modelVersion>
  <licenses>
    <license>
      <name>Apache 2</name>
      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>missing-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <version>1.0.0</version>
</project>`))
	require.NoError(t, err)

	licenses, err := NewResolver(nil, DefaultConfig()).ResolveLicenses(t.Context(), pom)
	require.NoError(t, err)
	require.Len(t, licenses, 1)
	require.NotNil(t, licenses[0].Name)
	require.Equal(t, "Apache 2", *licenses[0].Name)
	require.NotNil(t, licenses[0].URL)
	require.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0.txt", *licenses[0].URL)
}
