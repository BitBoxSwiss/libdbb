# Copyright (c) 2017 Shift Devices AG
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
.PHONY: deploy FORCE

empty :=
space := $(empty) $(empty)

COVERAGE_INFO = baseline_filtered_combined.info baseline.info \
  leveldb_baseline.info total_coverage.info \
  baseline_filtered.info functional_test.info functional_test_filtered.info \
  leveldb_baseline_filtered.info

#dist-hook:
#	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -


.INTERMEDIATE: $(COVERAGE_INFO)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

clean-local:
	rm -rf coverage_percent.txt test.coverage/ total.coverage/ test/tmp/ cache/ $(OSX_APP)
	rm -rf test/functional/__pycache__
