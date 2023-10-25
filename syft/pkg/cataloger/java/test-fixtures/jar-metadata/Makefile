CACHE_DIR = cache
CACHE_PATH = $(shell pwd)/cache

JACKSON_CORE = jackson-core-2.15.2
SBT_JACKSON_CORE = com.fasterxml.jackson.core.jackson-core-2.15.2

$(CACHE_DIR):
	mkdir -p $(CACHE_DIR)

$(CACHE_DIR)/$(JACKSON_CORE).jar: $(CACHE_DIR)
	cd $(JACKSON_CORE) && zip -r $(CACHE_PATH)/$(JACKSON_CORE).jar .

$(CACHE_DIR)/$(SBT_JACKSON_CORE).jar: $(CACHE_DIR)
	cd $(SBT_JACKSON_CORE) && zip -r $(CACHE_PATH)/$(SBT_JACKSON_CORE).jar .
