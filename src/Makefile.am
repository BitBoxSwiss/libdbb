# Copyright (c) 2017 Shift Devices AG
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = hidapi

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

#if EMBEDDED_UNIVALUE
#LIBUNIVALUE = univalue/libunivalue.la
#
#$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
#	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
#else
#LIBUNIVALUE = $(UNIVALUE_LIBS)
#endif

#$(UNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
#	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

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

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =

LIBDBB=libdbb.la
  
LIBDBB_H = \
  dbb.h

libdbb_la_SOURCES = dbb.cpp $(LIBDBB_H)
  
libdbb_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libdbb_la_LIBADD = $(HIDAPI)
libdbb_la_CPPFLAGS = $(AM_CPPFLAGS)
libdbb_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

lib_LTLIBRARIES = $(LIBDBB)

if ENABLE_TESTS
  bin_PROGRAMS += test
  test_SOURCES = test.cpp $(LIBDBB)
endif

clean-local:
	-$(MAKE) -C hidapi clean
	-$(MAKE) -C univalue clean