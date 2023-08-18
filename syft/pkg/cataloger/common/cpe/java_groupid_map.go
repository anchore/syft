package cpe

var defaultArtifactIDToGroupID = map[string]string{
	"ant":                            "org.apache.ant",
	"ant-antlr":                      "org.apache.ant",
	"ant-antunit":                    "org.apache.ant",
	"ant-apache-bcel":                "org.apache.ant",
	"ant-apache-bsf":                 "org.apache.ant",
	"ant-apache-log4j":               "org.apache.ant",
	"ant-apache-oro":                 "org.apache.ant",
	"ant-apache-regexp":              "org.apache.ant",
	"ant-apache-resolver":            "org.apache.ant",
	"ant-apache-xalan2":              "org.apache.ant",
	"ant-commons-logging":            "org.apache.ant",
	"ant-commons-net":                "org.apache.ant",
	"ant-compress":                   "org.apache.ant",
	"ant-dotnet":                     "org.apache.ant",
	"ant-imageio":                    "org.apache.ant",
	"ant-jai":                        "org.apache.ant",
	"ant-jakartamail":                "org.apache.ant",
	"ant-javamail":                   "org.apache.ant",
	"ant-jdepend":                    "org.apache.ant",
	"ant-jmf":                        "org.apache.ant",
	"ant-jsch":                       "org.apache.ant",
	"ant-junit":                      "org.apache.ant",
	"ant-junit4":                     "org.apache.ant",
	"ant-junitlauncher":              "org.apache.ant",
	"ant-launcher":                   "org.apache.ant",
	"ant-netrexx":                    "org.apache.ant",
	"ant-nodeps":                     "org.apache.ant",
	"ant-parent":                     "org.apache.ant",
	"ant-starteam":                   "org.apache.ant",
	"ant-stylebook":                  "org.apache.ant",
	"ant-swing":                      "org.apache.ant",
	"ant-testutil":                   "org.apache.ant",
	"ant-trax":                       "org.apache.ant",
	"ant-weblogic":                   "org.apache.ant",
	"ant-xz":                         "org.apache.ant",
	"spring":                         "org.springframework",
	"spring-amqp":                    "org.springframework.amqp",
	"spring-batch-core":              "org.springframework.batch",
	"spring-beans":                   "org.springframework",
	"spring-boot":                    "org.springframework.boot",
	"spring-boot-starter-web":        "org.springframework.boot",
	"spring-boot-starter-webflux":    "org.springframework.boot",
	"spring-cloud-function-context":  "org.springframework.cloud",
	"spring-cloud-function-parent":   "org.springframework.cloud",
	"spring-cloud-gateway":           "org.springframework.cloud",
	"spring-cloud-openfeign-core":    "org.springframework.cloud",
	"spring-cloud-task-dependencies": "org.springframework.cloud",
	"spring-core":                    "org.springframework",
	"spring-data-jpa":                "org.springframework.data",
	"spring-data-mongodb":            "org.springframework.data",
	"spring-data-rest-core":          "org.springframework.data",
	"spring-expression":              "org.springframework",
	"spring-integration-zip":         "org.springframework.integration",
	"spring-oxm":                     "org.springframework",
	"spring-security-core":           "org.springframework.security",
	"spring-security-config":         "org.springframework.security",
	"spring-security-oauth":          "org.springframework.security.oauth",
	"spring-security-oauth-parent":   "org.springframework.security.oauth",
	"spring-security-oauth2-client":  "org.springframework.security",
	"spring-session-core":            "org.springframework.session",
	"spring-vault-core":              "org.springframework.vault",
	"spring-web":                     "org.springframework",
	"spring-webflow":                 "org.springframework.webflow",
	"spring-webflux":                 "org.springframework",
	"spring-webmvc":                  "org.springframework",
}