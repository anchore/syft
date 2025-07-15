package php

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_InterpreterCataloger(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
	}{
		{
			name:    "native installation with extensions",
			fixture: "image-extensions",
			expectedPkgs: []string{
				// interpreters
				"php-cli @ 8.3.22 (/usr/local/bin/php)",
				"php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",

				// extensions
				"bcmath @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so)",
				"exif @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/exif.so)",
				"ftp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ftp.so)",
				"gd @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gd.so)",
				"gmp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gmp.so)",
				"intl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/intl.so)",
				"ldap @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ldap.so)",
				"opcache @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/opcache.so)",
				"pcntl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pcntl.so)",
				"pdo_mysql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_mysql.so)",
				"pdo_pgsql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_pgsql.so)",
				"sodium @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sodium.so)",
				"sysvsem @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sysvsem.so)",
				"zip @ 1.22.3 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/zip.so)",
			},
			expectedRels: []string{
				"bcmath @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"bcmath @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"exif @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/exif.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"exif @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/exif.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"ftp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ftp.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"ftp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ftp.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"gd @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gd.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"gd @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gd.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"gmp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gmp.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"gmp @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/gmp.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"intl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/intl.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"intl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/intl.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"ldap @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ldap.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"ldap @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/ldap.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"opcache @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/opcache.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"opcache @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/opcache.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"pcntl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pcntl.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"pcntl @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pcntl.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"pdo_mysql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_mysql.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"pdo_mysql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_mysql.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"pdo_pgsql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_pgsql.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"pdo_pgsql @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/pdo_pgsql.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"sodium @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sodium.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"sodium @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sodium.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"sysvsem @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sysvsem.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"sysvsem @ 8.3.22 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/sysvsem.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
				"zip @ 1.22.3 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/zip.so) [dependency-of] php-cli @ 8.3.22 (/usr/local/bin/php)",
				"zip @ 1.22.3 (/usr/local/lib/php/extensions/no-debug-non-zts-20230831/zip.so) [dependency-of] php-fpm @ 8.3.22 (/usr/local/sbin/php-fpm)",
			},
		},
		{
			name:    "apache installation with libphp and extensions",
			fixture: "image-apache",
			expectedPkgs: []string{
				// interpreters
				"libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",

				// extensions
				"calendar @ 8.2.28 (/usr/lib/php/20220829/calendar.so)",
				"ctype @ 8.2.28 (/usr/lib/php/20220829/ctype.so)",
				"exif @ 8.2.28 (/usr/lib/php/20220829/exif.so)",
				"ffi @ 8.2.28 (/usr/lib/php/20220829/ffi.so)",
				"fileinfo @ 8.2.28 (/usr/lib/php/20220829/fileinfo.so)",
				"ftp @ 8.2.28 (/usr/lib/php/20220829/ftp.so)",
				"gettext @ 8.2.28 (/usr/lib/php/20220829/gettext.so)",
				"iconv @ 8.2.28 (/usr/lib/php/20220829/iconv.so)",
				"mysqli @ 8.2.28 (/usr/lib/php/20220829/mysqli.so)",
				"opcache @ 8.2.28 (/usr/lib/php/20220829/opcache.so)",
				"pdo @ 8.2.28 (/usr/lib/php/20220829/pdo.so)",
				"pdo_mysql @ 8.2.28 (/usr/lib/php/20220829/pdo_mysql.so)",
				"phar @ 8.2.28 (/usr/lib/php/20220829/phar.so)",
				"posix @ 8.2.28 (/usr/lib/php/20220829/posix.so)",
				"readline @ 8.2.28 (/usr/lib/php/20220829/readline.so)",
				"shmop @ 8.2.28 (/usr/lib/php/20220829/shmop.so)",
				"simplexml @ 8.2.28 (/usr/lib/php/20220829/simplexml.so)",
				"sockets @ 8.2.28 (/usr/lib/php/20220829/sockets.so)",
				"sysvmsg @ 8.2.28 (/usr/lib/php/20220829/sysvmsg.so)",
				"sysvsem @ 8.2.28 (/usr/lib/php/20220829/sysvsem.so)",
				"sysvshm @ 8.2.28 (/usr/lib/php/20220829/sysvshm.so)",
				"tokenizer @ 8.2.28 (/usr/lib/php/20220829/tokenizer.so)",
				"xml @ 8.2.28 (/usr/lib/php/20220829/xml.so)",
				"xmlreader @ 8.2.28 (/usr/lib/php/20220829/xmlreader.so)",
				"xmlwriter @ 8.2.28 (/usr/lib/php/20220829/xmlwriter.so)",
				"xsl @ 8.2.28 (/usr/lib/php/20220829/xsl.so)",
			},
			expectedRels: []string{
				"calendar @ 8.2.28 (/usr/lib/php/20220829/calendar.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"ctype @ 8.2.28 (/usr/lib/php/20220829/ctype.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"exif @ 8.2.28 (/usr/lib/php/20220829/exif.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"ffi @ 8.2.28 (/usr/lib/php/20220829/ffi.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"fileinfo @ 8.2.28 (/usr/lib/php/20220829/fileinfo.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"ftp @ 8.2.28 (/usr/lib/php/20220829/ftp.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"gettext @ 8.2.28 (/usr/lib/php/20220829/gettext.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"iconv @ 8.2.28 (/usr/lib/php/20220829/iconv.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"mysqli @ 8.2.28 (/usr/lib/php/20220829/mysqli.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"opcache @ 8.2.28 (/usr/lib/php/20220829/opcache.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"pdo @ 8.2.28 (/usr/lib/php/20220829/pdo.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"pdo_mysql @ 8.2.28 (/usr/lib/php/20220829/pdo_mysql.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"phar @ 8.2.28 (/usr/lib/php/20220829/phar.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"posix @ 8.2.28 (/usr/lib/php/20220829/posix.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"readline @ 8.2.28 (/usr/lib/php/20220829/readline.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"shmop @ 8.2.28 (/usr/lib/php/20220829/shmop.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"simplexml @ 8.2.28 (/usr/lib/php/20220829/simplexml.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"sockets @ 8.2.28 (/usr/lib/php/20220829/sockets.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"sysvmsg @ 8.2.28 (/usr/lib/php/20220829/sysvmsg.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"sysvsem @ 8.2.28 (/usr/lib/php/20220829/sysvsem.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"sysvshm @ 8.2.28 (/usr/lib/php/20220829/sysvshm.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"tokenizer @ 8.2.28 (/usr/lib/php/20220829/tokenizer.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"xml @ 8.2.28 (/usr/lib/php/20220829/xml.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"xmlreader @ 8.2.28 (/usr/lib/php/20220829/xmlreader.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"xmlwriter @ 8.2.28 (/usr/lib/php/20220829/xmlwriter.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
				"xsl @ 8.2.28 (/usr/lib/php/20220829/xsl.so) [dependency-of] libphp @ 8.2.28 (/usr/lib/apache2/modules/libphp8.2.so)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewInterpreterCataloger()
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				//Expects(tt.expected, nil).
				ExpectsPackageStrings(tt.expectedPkgs).
				ExpectsRelationshipStrings(tt.expectedRels).
				TestCataloger(t, c)
		})
	}
}
