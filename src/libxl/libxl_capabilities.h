/*
 * libxl_capabilities.h: libxl capabilities generation
 *
 * Copyright (C) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#ifndef LIBVIRT_LIBXL_CAPABILITIES_H
# define LIBVIRT_LIBXL_CAPABILITIES_H

# include <libxl.h>

# include "virobject.h"
# include "capabilities.h"
# include "domain_capabilities.h"
# include "virfirmware.h"


# ifndef LIBXL_FIRMWARE_DIR
#  define LIBXL_FIRMWARE_DIR "/usr/lib/xen/boot"
# endif
# ifndef LIBXL_EXECBIN_DIR
#  define LIBXL_EXECBIN_DIR "/usr/lib/xen/bin"
# endif

/* Used for prefix of ifname of any network name generated dynamically
 * by libvirt for Xen, and cannot be used for a persistent network name.  */
# define LIBXL_GENERATED_PREFIX_XEN "vif"

bool libxlCapsHasPVUSB(void);

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx);

int
libxlMakeDomainCapabilities(virDomainCapsPtr domCaps,
                            virFirmwarePtr *firmwares,
                            size_t nfirmwares);

int
libxlDomainGetEmulatorType(const virDomainDef *def);

#endif /* LIBVIRT_LIBXL_CAPABILITIES_H */
