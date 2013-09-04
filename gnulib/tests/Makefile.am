## Makefile for gnulib/lib

## Copyright (C) 2011, 2013 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

include gnulib.mk

INCLUDES = $(GETTEXT_CPPFLAGS)

GNULIB_TESTS0 =
GNULIB_TESTS1 = $(GNULIB_TESTS)
if WITH_EXPENSIVE_TESTS
## Automake requires that at least one conditional call out all tests to
## be run, for those tests to be shipped in the tarball
TESTS = $(GNULIB_TESTS)
endif WITH_EXPENSIVE_TESTS
## However, we want to change the set of tests based on the make environment,
## where the default was set at configure time.  Use GNU make constructs to
## hide our actions from Automake, so we don't get it too confused.
VIR_TEST_EXPENSIVE ?= $(VIR_TEST_EXPENSIVE_DEFAULT)
$(eval TESTS=$(GNULIB_TESTS$(VIR_TEST_EXPENSIVE)))
