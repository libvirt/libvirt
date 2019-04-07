/*
 * bhyve_capabilities.h: bhyve capabilities module
 *
 * Copyright (C) 2014 Semihalf
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
 *
 */

#ifndef LIBVIRT_BHYVE_CAPABILITIES_H
# define LIBVIRT_BHYVE_CAPABILITIES_H

# include "capabilities.h"
# include "conf/domain_capabilities.h"

# include "bhyve_utils.h"

virCapsPtr virBhyveCapsBuild(void);
int virBhyveDomainCapsFill(virDomainCapsPtr caps,
                           unsigned int bhyvecaps,
                           virDomainCapsStringValuesPtr firmwares);
virDomainCapsPtr virBhyveDomainCapsBuild(bhyveConnPtr,
                                         const char *emulatorbin,
                                         const char *machine,
                                         virArch arch,
                                         virDomainVirtType virttype);

/* These are bit flags: */
typedef enum {
    BHYVE_GRUB_CAP_CONSDEV = 1,
} virBhyveGrubCapsFlags;

typedef enum {
    BHYVE_CAP_RTC_UTC = 1 << 0,
    BHYVE_CAP_AHCI32SLOT = 1 << 1,
    BHYVE_CAP_NET_E1000 = 1 << 2,
    BHYVE_CAP_LPC_BOOTROM = 1 << 3,
    BHYVE_CAP_FBUF = 1 << 4,
    BHYVE_CAP_XHCI = 1 << 5,
    BHYVE_CAP_CPUTOPOLOGY = 1 << 6,
} virBhyveCapsFlags;

int virBhyveProbeGrubCaps(virBhyveGrubCapsFlags *caps);
int virBhyveProbeCaps(unsigned int *caps);

#endif /* LIBVIRT_BHYVE_CAPABILITIES_H */
