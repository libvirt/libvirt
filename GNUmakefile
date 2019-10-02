# Having a separate GNUmakefile lets me 'include' the dynamically
# generated rules created via cfg.mk (package-local configuration)
# as well as maint.mk (generic maintainer rules).
# This makefile is used only if you run GNU Make.
# It is necessary if you want to build targets usually of interest
# only to the maintainer.

# Copyright (C) 2001, 2003, 2006-2019 Free Software Foundation, Inc.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

_build-aux ?= build-aux
_autoreconf ?= autoreconf -v

# If the user runs GNU make but has not yet run ./configure,
# give them a diagnostic.
_gl-Makefile := $(wildcard [M]akefile)
ifneq ($(_gl-Makefile),)

# Make tar archive easier to reproduce.
export TAR_OPTIONS = --owner=0 --group=0 --numeric-owner

# Allow the user to add to this in the Makefile.
ALL_RECURSIVE_TARGETS =

include Makefile
include $(srcdir)/$(_build-aux)/cfg.mk
include $(srcdir)/$(_build-aux)/maint.mk

else

.DEFAULT_GOAL := abort-due-to-no-makefile
srcdir = .

# The package can override .DEFAULT_GOAL to run actions like autoreconf.
include $(srcdir)/$(_build-aux)/cfg.mk
include $(srcdir)/$(_build-aux)/maint.mk

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
$(MAKECMDGOALS): abort-due-to-no-makefile
endif

abort-due-to-no-makefile:
	@echo There seems to be no Makefile in this directory.   1>&2
	@echo "You must run ./configure before running 'make'." 1>&2
	@exit 1

endif

# Tell version 3.79 and up of GNU make to not build goals in this
# directory in parallel, in case someone tries to build multiple
# targets, and one of them can cause a recursive target to be invoked.

# Only set this if Automake doesn't provide it.
AM_RECURSIVE_TARGETS ?= $(RECURSIVE_TARGETS:-recursive=) \
  $(RECURSIVE_CLEAN_TARGETS:-recursive=) \
  dist distcheck tags ctags

ALL_RECURSIVE_TARGETS += $(AM_RECURSIVE_TARGETS)

ifneq ($(word 2, $(MAKECMDGOALS)), )
ifneq ($(filter $(ALL_RECURSIVE_TARGETS), $(MAKECMDGOALS)), )
.NOTPARALLEL:
endif
endif
