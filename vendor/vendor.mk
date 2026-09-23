# Define the vendor include directory path
VENDOR_INC_DIR = $(ONEWIFI_EM_HOME)/vendor/inc

# Add the include path to CXXFLAGS (for C++ .cpp files) and CFLAGS
CXXFLAGS += -I$(VENDOR_INC_DIR)
CFLAGS   += -I$(VENDOR_INC_DIR)

# (Optional) If using standard local Make variables instead of OpenWrt build targets:
# INCLUDES += -I$(VENDOR_INC_DIR)

VENDOR_AGENT_SOURCES = \
    $(wildcard $(ONEWIFI_EM_HOME)/vendor/src/common/*.cpp) \
    $(wildcard $(ONEWIFI_EM_HOME)/vendor/src/agent/*.cpp)

VENDOR_CTRL_SOURCES = \
    $(wildcard $(ONEWIFI_EM_HOME)/vendor/src/common/*.cpp) \
    $(wildcard $(ONEWIFI_EM_HOME)/vendor/src/ctrl/*.cpp)

# Vendor feature flags
CXXFLAGS += -DEM_WEBSOCKET_PUSH