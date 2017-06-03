# Copyright (c) 2017 Shift Devices AG
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = hidapi univalue

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =


LIBUNIVALUE = univalue/libunivalue.la
$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

UNIVALUE_INCLUDES = -I$(srcdir)/univalue/include

if TARGET_WINDOWS
  HIDAPI=hidapi/windows/libhidapi.la
endif

if TARGET_OSX
  HIDAPI=hidapi/mac/libhidapi.la
endif

if TARGET_LINUX
  HIDAPI=hidapi/libusb/libhidapi-libusb.la
endif

$(HIDAPI):
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

HIDAPI_INCLUDES = -I$(srcdir)/hidapi

LIBDBB_INCLUDES = $(HIDAPI_INCLUDES) $(UNIVALUE_INCLUDES)

CTAES = \
  crypto/ctaes/ctaes.c \
  crypto/ctaes/ctaes.h

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =

LIBDBB=libdbb.la
  
LIBDBB_H = \
  compat/byteswap.h \
  compat/endian.h \
  compat.h \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/common.h \
  crypto/random.h \
  crypto/sha512.h \
  dbb.h \
  support/cleanse.h \
  uint256.h \
  utilstrencodings.h

libdbb_la_SOURCES = \
  crypto/aes.cpp \
  crypto/chacha20.cpp \
  crypto/random.cpp \
  crypto/sha512.cpp \
  dbb.cpp \
  support/cleanse.cpp \
  utilstrencodings.cpp \
  uint256.cpp \
  $(LIBDBB_H) \
  $(CTAES)
  
libdbb_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libdbb_la_LIBADD = $(HIDAPI) $(LIBUNIVALUE)
libdbb_la_CPPFLAGS = $(AM_CPPFLAGS) $(LIBDBB_INCLUDES)
libdbb_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

lib_LTLIBRARIES = $(LIBDBB)

if ENABLE_TESTS
  bin_PROGRAMS += test
  test_SOURCES = test.cpp
  test_CPPFLAGS = $(AM_CPPFLAGS) $(LIBDBB_INCLUDES)
  test_LDADD = $(LIBDBB)
endif

clean-local:
	-$(MAKE) -C hidapi clean
	-$(MAKE) -C univalue clean