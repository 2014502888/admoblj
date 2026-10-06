TARGET := iphone:clang:latest:14.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RivoVPNAD
RivoVPNAD_FILES = Tweak.x fishhook.c
RivoVPNAD_CFLAGS = -fobjc-arc
RivoVPNAD_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS_MAKE_PATH)/tweak.mk
