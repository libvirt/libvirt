/*
 * xenxs_private.h: Private definitions for Xen parsing
 *
 * Copyright (C) 2007, 2010, 2012 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "internal.h"

#include <xen/xen.h>

/* xen-unstable changeset 19788 removed MAX_VIRT_CPUS from public
 * headers.  Its semantic was retained with XEN_LEGACY_MAX_VCPUS.
 * Ensure MAX_VIRT_CPUS is defined accordingly.
 */
#if !defined(MAX_VIRT_CPUS) && defined(XEN_LEGACY_MAX_VCPUS)
# define MAX_VIRT_CPUS XEN_LEGACY_MAX_VCPUS
#endif

#define MIN_XEN_GUEST_SIZE 64  /* 64 megabytes */

#ifdef __sun
# define DEFAULT_VIF_SCRIPT "vif-vnic"
#else
# define DEFAULT_VIF_SCRIPT "vif-bridge"
#endif
