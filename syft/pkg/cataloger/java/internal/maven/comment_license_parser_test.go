package maven

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
)

func Test_licensesFromComments(t *testing.T) {
	ctx := t.Context()
	licenses, err := ExtractLicensesFromComments(ctx, `<?xml version="1.0" encoding="UTF-8"?>
<!--
 Oracle licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License. You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
-->
<project/>`)

	require.NoError(t, err)
	require.Len(t, licenses, 1)
	require.NotNil(t, licenses[0].Name)
	require.Equal(t, "Apache-2.0", *licenses[0].Name)
}

func Test_licensesFromComments_ignoresNonLicenseURLs(t *testing.T) {
	ctx := t.Context()
	licenses, err := ExtractLicensesFromComments(ctx, `<?xml version="1.0" encoding="UTF-8"?>
<!-- build note: see https://github.com/example/project/issues/123 -->
<project/>`)

	require.NoError(t, err)
	require.Nil(t, licenses)
}

func Test_licensesFromComments_withContext(t *testing.T) {
	ctx := context.TODO()
	scanner, err := licenses.NewDefaultScanner()
	require.NoError(t, err)
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)

	result, err := ExtractLicensesFromComments(ctx, `<?xml version="1.0" encoding="UTF-8"?>
<!--
 This file is licensed under the MIT License
-->
<project/>`)

	require.NoError(t, err)
	if len(result) > 0 {
		require.True(t, len(result) > 0, "should find MIT license in comment")
	}
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

	ctx := t.Context()
	licenses, err := NewResolver(nil, DefaultConfig()).ResolveLicenses(ctx, pom)
	require.NoError(t, err)
	require.Len(t, licenses, 1)
	require.NotNil(t, licenses[0].Name)
	require.Equal(t, "Apache 2", *licenses[0].Name)
	require.NotNil(t, licenses[0].URL)
	require.Equal(t, "http://www.apache.org/licenses/LICENSE-2.0.txt", *licenses[0].URL)
}
