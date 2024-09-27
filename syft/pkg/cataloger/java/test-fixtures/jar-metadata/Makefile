CACHE_DIR = cache
CACHE_PATH = $(shell pwd)/cache
FINGERPRINT_FILE=$(CACHE_DIR).fingerprint

ifndef CACHE_DIR
    $(error CACHE_DIR is not set)
endif

JACKSON_CORE = jackson-core-2.15.2
SBT_JACKSON_CORE = com.fasterxml.jackson.core.jackson-core-2.15.2
OPENSAML_CORE = opensaml-core-3.4.6
API_ALL_SOURCES = api-all-2.0.0-sources
SPRING_INSTRUMENTATION = spring-instrumentation-4.3.0-1.0
MULTIPLE_MATCHING = multiple-matching-2.11.5


.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: $(CACHE_DIR)

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(FINGERPRINT_FILE)

$(CACHE_DIR): $(CACHE_DIR)/$(JACKSON_CORE).jar $(CACHE_DIR)/$(SBT_JACKSON_CORE).jar $(CACHE_DIR)/$(OPENSAML_CORE).jar  $(CACHE_DIR)/$(API_ALL_SOURCES).jar $(CACHE_DIR)/$(SPRING_INSTRUMENTATION).jar $(CACHE_DIR)/$(MULTIPLE_MATCHING).jar

$(CACHE_DIR)/$(JACKSON_CORE).jar:
	mkdir -p $(CACHE_DIR)
	cd $(JACKSON_CORE) && zip -r $(CACHE_PATH)/$(JACKSON_CORE).jar .

$(CACHE_DIR)/$(SBT_JACKSON_CORE).jar:
	mkdir -p $(CACHE_DIR)
	cd $(SBT_JACKSON_CORE) && zip -r $(CACHE_PATH)/$(SBT_JACKSON_CORE).jar .

$(CACHE_DIR)/$(OPENSAML_CORE).jar:
	mkdir -p $(CACHE_DIR)
	cd $(OPENSAML_CORE) && zip -r $(CACHE_PATH)/$(OPENSAML_CORE).jar .

$(CACHE_DIR)/$(API_ALL_SOURCES).jar:
	mkdir -p $(CACHE_DIR)
	cd $(API_ALL_SOURCES) && zip -r $(CACHE_PATH)/$(API_ALL_SOURCES).jar .

$(CACHE_DIR)/$(SPRING_INSTRUMENTATION).jar:
	mkdir -p $(CACHE_DIR)
	cd $(SPRING_INSTRUMENTATION) && zip -r $(CACHE_PATH)/$(SPRING_INSTRUMENTATION).jar .

$(CACHE_DIR)/$(MULTIPLE_MATCHING).jar:
	mkdir -p $(CACHE_DIR)
	cd $(MULTIPLE_MATCHING) && zip -r $(CACHE_PATH)/$(MULTIPLE_MATCHING).jar .

# Jenkins plugins typically do not have the version included in the archive name, 
# so it is important to not include it in the generated test fixture
$(CACHE_DIR)/gradle.hpi:
	mkdir -p $(CACHE_DIR)
	cd jenkins-plugins/gradle/2.11 && zip -r $(CACHE_PATH)/gradle.hpi .

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find . ! -path '*/cache*'  -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)
	@#cat $(FINGERPRINT_FILE) | sha256sum | awk '{print $$1}'

# requirement 4: 'clean' goal to remove all generated test fixtures
clean:
	rm -rf $(CACHE_DIR)/* $(FINGERPRINT_FILE)
