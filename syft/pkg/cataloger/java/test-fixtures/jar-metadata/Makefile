CACHE_DIR = cache
CACHE_PATH = $(shell pwd)/cache

JACKSON_CORE = jackson-core-2.15.2
SBT_JACKSON_CORE = com.fasterxml.jackson.core.jackson-core-2.15.2
OPENSAML_CORE = opensaml-core-3.4.6
API_ALL_SOURCES = api-all-2.0.0-sources
SPRING_INSTRUMENTATION = spring-instrumentation-4.3.0-1.0
MULTIPLE_MATCHING = multiple-matching-2.11.5

$(CACHE_DIR):
	mkdir -p $(CACHE_DIR)

$(CACHE_DIR)/$(JACKSON_CORE).jar: $(CACHE_DIR)
	cd $(JACKSON_CORE) && zip -r $(CACHE_PATH)/$(JACKSON_CORE).jar .

$(CACHE_DIR)/$(SBT_JACKSON_CORE).jar: $(CACHE_DIR)
	cd $(SBT_JACKSON_CORE) && zip -r $(CACHE_PATH)/$(SBT_JACKSON_CORE).jar .

$(CACHE_DIR)/$(OPENSAML_CORE).jar: $(CACHE_DIR)
	cd $(OPENSAML_CORE) && zip -r $(CACHE_PATH)/$(OPENSAML_CORE).jar .

$(CACHE_DIR)/$(API_ALL_SOURCES).jar: $(CACHE_DIR)
	cd $(API_ALL_SOURCES) && zip -r $(CACHE_PATH)/$(API_ALL_SOURCES).jar .

$(CACHE_DIR)/$(SPRING_INSTRUMENTATION).jar: $(CACHE_DIR)
	cd $(SPRING_INSTRUMENTATION) && zip -r $(CACHE_PATH)/$(SPRING_INSTRUMENTATION).jar .

$(CACHE_DIR)/$(MULTIPLE_MATCHING).jar: $(CACHE_DIR)
	cd $(MULTIPLE_MATCHING) && zip -r $(CACHE_PATH)/$(MULTIPLE_MATCHING).jar .
