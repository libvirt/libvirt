/*
 * xenxs_private.h: Private definitions for Xen parsing
 *
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2007, 2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Richard W.M. Jones <rjones@redhat.com>
 * Author: Markus Groß <gross@univention.de>
 */

#ifndef __VIR_XENXS_PRIVATE_H__
# define __VIR_XENXS_PRIVATE_H__

# include "internal.h"

# include <stdint.h>
# include <xen/xen.h>
# include "xen_sxpr.h"

/* xen-unstable changeset 19788 removed MAX_VIRT_CPUS from public
 * headers.  Its semantic was retained with XEN_LEGACY_MAX_VCPUS.
 * Ensure MAX_VIRT_CPUS is defined accordingly.
 */
# if !defined(MAX_VIRT_CPUS) && defined(XEN_LEGACY_MAX_VCPUS)
#  define MAX_VIRT_CPUS XEN_LEGACY_MAX_VCPUS
# endif

# ifdef WITH_RHEL5_API
#  define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 0
#  define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF XEND_CONFIG_VERSION_3_0_3
# else
#  define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU XEND_CONFIG_VERSION_3_0_4
#  define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF XEND_CONFIG_VERSION_3_0_4
# endif

# define MIN_XEN_GUEST_SIZE 64  /* 64 megabytes */

# ifdef __sun
#  define DEFAULT_VIF_SCRIPT "vif-vnic"
# else
#  define DEFAULT_VIF_SCRIPT "vif-bridge"
# endif

# define VIR_FROM_THIS VIR_FROM_NONE

# define XENXS_ERROR(code, ...)                                               \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__, __FUNCTION__,         \
                         __LINE__, __VA_ARGS__)

#endif /* __VIR_XENXS_PRIVATE_H__ */
