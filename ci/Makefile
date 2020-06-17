# -*- makefile -*-
# vim: filetype=make

# The root directory of the libvirt.git checkout
CI_GIT_ROOT = $(shell git rev-parse --show-toplevel)

# The root directory for all CI-related contents
CI_ROOTDIR = $(CI_GIT_ROOT)/ci

# The directory holding content on the host that we will
# expose to the container.
CI_SCRATCHDIR = $(CI_ROOTDIR)/scratch

# The directory holding the clone of the git repo that
# we will expose to the container
CI_HOST_SRCDIR = $(CI_SCRATCHDIR)/src

# The directory holding the source inside the
# container, i.e. where we want to expose
# the $(CI_HOST_SRCDIR) directory from the host
CI_CONT_SRCDIR = $(CI_USER_HOME)/libvirt

# Relative directory to perform the build in. This
# defaults to using a separate build dir, but can be
# set to empty string for an in-source tree build.
CI_VPATH = build

# The directory holding the build output inside the
# container.
CI_CONT_BUILDDIR = $(CI_CONT_SRCDIR)/$(CI_VPATH)

# Can be overridden with mingw{32,64}-configure if desired
CI_CONFIGURE = $(CI_CONT_SRCDIR)/configure

# Default to using all possible CPUs
CI_SMP = $(shell getconf _NPROCESSORS_ONLN)

# Any extra arguments to pass to make
CI_MAKE_ARGS =

# Any extra arguments to pass to configure
CI_CONFIGURE_ARGS =

# Script containing environment preparation steps
CI_PREPARE_SCRIPT = $(CI_ROOTDIR)/prepare.sh

# Script containing build instructions
CI_BUILD_SCRIPT = $(CI_ROOTDIR)/build.sh

# Location of the container images we're going to pull
# Can be useful to override to use a locally built
# image instead
CI_IMAGE_PREFIX = registry.gitlab.com/libvirt/libvirt/ci-

# The default tag is ':latest' but if the container
# repo above uses different conventions this can override it
CI_IMAGE_TAG = :latest

# We delete the virtual root after completion, set
# to 0 if you need to keep it around for debugging
CI_CLEAN = 1

# We'll always freshly clone the virtual root each
# time in case it was not cleaned up before. Set
# to 1 if you want to try restarting a previously
# preserved env
CI_REUSE = 0

# We need the container process to run with current host IDs
# so that it can access the passed in build directory
CI_UID = $(shell id -u)
CI_GID = $(shell id -g)

# We also need the user's login and home directory to prepare the
# environment the way some programs expect it
CI_USER_LOGIN = $(shell echo "$$USER")
CI_USER_HOME = $(shell echo "$$HOME")

CI_ENGINE = auto
# Container engine we are going to use, can be overridden per make
# invocation, if it is not we try podman and then default to docker.
ifeq ($(CI_ENGINE),auto)
	override CI_ENGINE = $(shell podman version >/dev/null 2>&1 && echo podman || echo docker)
endif

# IDs you run as do not need to exist in
# the container's /etc/passwd & /etc/group files, but
# if they do not, then libvirt's 'make check' will fail
# many tests.

# We do not directly mount /etc/{passwd,group} as Docker
# is liable to mess with SELinux labelling which will
# then prevent the host accessing them. And podman cannot
# relabel the files due to it running rootless. So
# copying them first is safer and less error-prone.
CI_PWDB_MOUNTS = \
	--volume $(CI_SCRATCHDIR)/group:/etc/group:ro,z \
	--volume $(CI_SCRATCHDIR)/passwd:/etc/passwd:ro,z \
	$(NULL)

CI_HOME_MOUNTS = \
	--volume $(CI_SCRATCHDIR)/home:$(CI_USER_HOME):z \
	$(NULL)

CI_SCRIPT_MOUNTS = \
	--volume $(CI_SCRATCHDIR)/prepare:$(CI_USER_HOME)/prepare:z \
	--volume $(CI_SCRATCHDIR)/build:$(CI_USER_HOME)/build:z \
	$(NULL)

# Docker containers can have very large ulimits
# for nofiles - as much as 1048576. This makes
# libvirt very slow at exec'ing programs.
CI_ULIMIT_FILES = 1024

ifeq ($(CI_ENGINE),podman)
	# Podman cannot reuse host namespace when running non-root
	# containers.  Until support for --keep-uid is added we can
	# just create another mapping that will do that for us.
	# Beware, that in {uid,git}map=container_id:host_id:range, the
	# host_id does actually refer to the uid in the first mapping
	# where 0 (root) is mapped to the current user and rest is
	# offset.
	#
	# In order to set up this mapping, we need to keep all the
	# user IDs to prevent possible errors as some images might
	# expect UIDs up to 90000 (looking at you fedora), so we don't
	# want the overflowuid to be used for them.  For mapping all
	# the other users properly, some math needs to be done.
	# Don't worry, it's just addition and subtraction.
	#
	# 65536 ought to be enough (tm), but for really rare cases the
	# maximums might need to be higher, but that only happens when
	# your /etc/sub{u,g}id allow users to have more IDs.  Unless
	# --keep-uid is supported, let's do this in a way that should
	# work for everyone.
	CI_MAX_UID = $(shell sed -n "s/^$(CI_USER_LOGIN):[^:]\+://p" /etc/subuid)
	CI_MAX_GID = $(shell sed -n "s/^$(CI_USER_LOGIN):[^:]\+://p" /etc/subgid)
	ifeq ($(CI_MAX_UID),)
		CI_MAX_UID = 65536
	endif
	ifeq ($(CI_MAX_GID),)
		CI_MAX_GID = 65536
	endif
	CI_UID_OTHER = $(shell echo $$(($(CI_UID)+1)))
	CI_GID_OTHER = $(shell echo $$(($(CI_GID)+1)))
	CI_UID_OTHER_RANGE = $(shell echo $$(($(CI_MAX_UID)-$(CI_UID))))
	CI_GID_OTHER_RANGE = $(shell echo $$(($(CI_MAX_GID)-$(CI_GID))))

	CI_PODMAN_ARGS = \
		--uidmap 0:1:$(CI_UID) \
		--uidmap $(CI_UID):0:1 \
		--uidmap $(CI_UID_OTHER):$(CI_UID_OTHER):$(CI_UID_OTHER_RANGE) \
		--gidmap 0:1:$(CI_GID) \
		--gidmap $(CI_GID):0:1 \
		--gidmap $(CI_GID_OTHER):$(CI_GID_OTHER):$(CI_GID_OTHER_RANGE) \
		$(NULL)
endif

# Args to use when cloning a git repo.
#  -c  stop it complaining about checking out a random hash
#  -q  stop it displaying progress info for local clone
#  --local ensure we don't actually copy files
CI_GIT_ARGS = \
	-c advice.detachedHead=false \
	-q \
	--local  \
	$(NULL)

# Args to use when running the container
#   --rm      stop inactive containers getting left behind
#   --user    we execute as the same user & group account
#             as dev so that file ownership matches host
#             instead of root:root
#   --volume  to pass in the cloned git repo & config
#   --ulimit  lower files limit for performance reasons
#   --interactive
#   --tty     Ensure we have ability to Ctrl-C the build
CI_ENGINE_ARGS = \
	--rm \
	--interactive \
	--tty \
	$(CI_PODMAN_ARGS) \
	$(CI_PWDB_MOUNTS) \
	$(CI_HOME_MOUNTS) \
	$(CI_SCRIPT_MOUNTS) \
	--volume $(CI_HOST_SRCDIR):$(CI_CONT_SRCDIR):z \
	--ulimit nofile=$(CI_ULIMIT_FILES):$(CI_ULIMIT_FILES) \
	--cap-add=SYS_PTRACE \
	$(NULL)

ci-check-engine:
	@echo -n "Checking if $(CI_ENGINE) is available..." && \
	$(CI_ENGINE) version 1>/dev/null && echo "yes"

ci-prepare-tree: ci-check-engine
	@test "$(CI_REUSE)" != "1" && rm -rf $(CI_SCRATCHDIR) || :
	@if ! test -d $(CI_SCRATCHDIR) ; then \
		mkdir -p $(CI_SCRATCHDIR); \
		cp /etc/passwd $(CI_SCRATCHDIR); \
		cp /etc/group $(CI_SCRATCHDIR); \
		mkdir -p $(CI_SCRATCHDIR)/home; \
		cp "$(CI_PREPARE_SCRIPT)" $(CI_SCRATCHDIR)/prepare; \
		cp "$(CI_BUILD_SCRIPT)" $(CI_SCRATCHDIR)/build; \
		chmod +x "$(CI_SCRATCHDIR)/prepare" "$(CI_SCRATCHDIR)/build"; \
		echo "Cloning $(CI_GIT_ROOT) to $(CI_HOST_SRCDIR)"; \
		git clone $(CI_GIT_ARGS) $(CI_GIT_ROOT) $(CI_HOST_SRCDIR) || exit 1; \
		for mod in $$(git submodule | awk '{ print $$2 }' | sed -E 's,^../,,g') ; \
		do \
			test -f $(CI_GIT_ROOT)/$$mod/.git || continue ; \
			echo "Cloning $(CI_GIT_ROOT)/$$mod to $(CI_HOST_SRCDIR)/$$mod"; \
			git clone $(CI_GIT_ARGS) $(CI_GIT_ROOT)/$$mod $(CI_HOST_SRCDIR)/$$mod || exit 1; \
		done ; \
	fi

ci-run-command@%: ci-prepare-tree
	$(CI_ENGINE) run $(CI_ENGINE_ARGS) $(CI_IMAGE_PREFIX)$*$(CI_IMAGE_TAG) \
		/bin/bash -c ' \
		$(CI_USER_HOME)/prepare || exit 1; \
		sudo \
		  --login \
		  --user="#$(CI_UID)" \
		  --group="#$(CI_GID)" \
		  CONFIGURE_OPTS="$$CONFIGURE_OPTS" \
		  CI_CONT_SRCDIR="$(CI_CONT_SRCDIR)" \
		  CI_CONT_BUILDDIR="$(CI_CONT_BUILDDIR)" \
		  CI_SMP="$(CI_SMP)" \
		  CI_CONFIGURE="$(CI_CONFIGURE)" \
		  CI_CONFIGURE_ARGS="$(CI_CONFIGURE_ARGS)" \
		  CI_MAKE_ARGS="$(CI_MAKE_ARGS)" \
		  $(CI_COMMAND) || exit 1'
	@test "$(CI_CLEAN)" = "1" && rm -rf $(CI_SCRATCHDIR) || :

ci-shell@%:
	$(MAKE) -C $(CI_ROOTDIR) ci-run-command@$* CI_COMMAND="/bin/bash"

ci-build@%:
	$(MAKE) -C $(CI_ROOTDIR) ci-run-command@$* CI_COMMAND="$(CI_USER_HOME)/build"

ci-check@%:
	$(MAKE) -C $(CI_ROOTDIR) ci-build@$* CI_MAKE_ARGS="check"

ci-list-images:
	@echo
	@echo "Available x86 container images:"
	@echo
	@sh list-images.sh "$(CI_IMAGE_PREFIX)" | grep -v cross
	@echo
	@echo "Available cross-compiler container images:"
	@echo
	@sh list-images.sh "$(CI_IMAGE_PREFIX)" | grep cross
	@echo

ci-help:
	@echo "Build libvirt inside containers used for CI"
	@echo
	@echo "Available targets:"
	@echo
	@echo "    ci-build@\$$IMAGE - run a default 'make'"
	@echo "    ci-check@\$$IMAGE - run a 'make check'"
	@echo "    ci-shell@\$$IMAGE - run an interactive shell"
	@echo "    ci-list-images  - list available images"
	@echo "    ci-help         - show this help message"
	@echo
	@echo "Available make variables:"
	@echo
	@echo "    CI_CLEAN=0          - do not delete '$(CI_SCRATCHDIR)' after completion"
	@echo "    CI_REUSE=1          - re-use existing '$(CI_SCRATCHDIR)' content"
	@echo "    CI_ENGINE=auto      - container engine to use (podman, docker)"
	@echo "    CI_CONFIGURE_ARGS=  - extra arguments passed to configure"
	@echo "    CI_MAKE_ARGS=       - extra arguments passed to make, e.g. space delimited list of targets"
	@echo
