package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_candidateVendorsForWordpressPlugin(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "Akismet Anti-spam: Spam Protection",
			pkg: pkg.Package{
				Name: "Akismet Anti-spam: Spam Protection",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "akismet",
					Author:                 "Automattic - Anti-spam Team",
					AuthorURI:              "https://automattic.com/wordpress-plugins/",
				},
			},
			expected: []string{"automattic - anti-spam team", "automattic"},
		},
		{
			name: "All-in-One WP Migration",
			pkg: pkg.Package{
				Name: "All-in-One WP Migration",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "all-in-one-wp-migration",
					AuthorURI:              "https://servmask.com",
				},
			},
			expected: []string{"servmask"},
		},
		{
			name: "Booking Ultra Pro Appointments Booking Calendar",
			pkg: pkg.Package{
				Name: "Booking Ultra Pro Appointments Booking Calendar",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "booking-ultra-pro",
					Author:                 "Booking Ultra Pro",
					AuthorURI:              "https://bookingultrapro.com/",
				},
			},
			expected: []string{"booking ultra pro", "bookingultrapro"},
		},
		{
			name: "Coming Soon Chop Chop",
			pkg: pkg.Package{
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "cc-coming-soon",
					Author:                 "Chop-Chop.org",
					AuthorURI:              "https://www.chop-chop.org",
				},
			},
			expected: []string{"chop-chop.org", "chop-chop"},
		},
		{
			name: "Access Code Feeder",
			pkg: pkg.Package{
				Name: "Access Code Feeder",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "access-code-feeder",
				},
			},
			// When a plugin as no `Author URI` use plugin_name + _project as a vendor
			expected: []string{"access_code_feeder_project"},
		},
		{
			name: "WP Coder",
			pkg: pkg.Package{
				Name: "WP Coder",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "wp-coder",
					Author:                 "Wow-Company",
					AuthorURI:              "https://wow-estore.com/",
				},
			},
			// found in the wild https://plugins.trac.wordpress.org/browser/wp-coder/tags/2.5.1/wp-coder.php
			expected: []string{
				"wow-company", // this is the correct answer relative to CPEs registered on CVE-2021-25053
				"wow-estore",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateVendorsForWordpressPlugin(test.pkg).uniqueValues()
			assert.ElementsMatch(t, test.expected, actual, "different vendors")
		})
	}
}

func Test_candidateProductsWordpressPlugin(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "All-in-One WP Migration",
			pkg: pkg.Package{
				Name: "All-in-One WP Migration",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "all-in-one-wp-migration",
				},
			},
			expected: []string{"all-in-one_wp_migration", "all-in-one-wp-migration"},
		},
		{
			name: "Akismet Anti-spam: Spam Protection",
			pkg: pkg.Package{
				Name: "Akismet Anti-spam: Spam Protection",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "akismet",
				},
			},
			expected: []string{"akismet_anti-spam:_spam_protection", "akismet"},
		},
		{
			name: "Access Code Feeder",
			pkg: pkg.Package{
				Name: "Access Code Feeder",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "access-code-feeder",
				},
			},
			expected: []string{"access_code_feeder", "access-code-feeder"},
		},
		{
			name: "CampTix Event Ticketing",
			pkg: pkg.Package{
				Name: "CampTix Event Ticketing",
				Metadata: pkg.WordpressPluginEntry{
					PluginInstallDirectory: "camptix",
				},
			},
			expected: []string{"camptix_event_ticketing", "camptix"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateProductsForWordpressPlugin(test.pkg).uniqueValues(), "different products")
		})
	}
}
