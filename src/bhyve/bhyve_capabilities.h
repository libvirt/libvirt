/*
 * bhyve_capabilities.h: bhyve capabilities module
 *
 * Copyright (C) 2014 Semihalf
 * Copyright (C) 2025 The FreeBSD Foundation
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

#pragma once

#include "capabilities.h"
#include "conf/domain_capabilities.h"
#include "virbitmap.h"

#include "bhyve_utils.h"

virCaps *virBhyveCapsBuild(void);
int virBhyveDomainCapsFill(virDomainCaps *caps,
                           virBitmap *bhyvecaps,
                           virDomainCapsStringValues *firmwares);
virDomainCaps *virBhyveDomainCapsBuild(bhyveConn *conn,
                                       const char *emulatorbin,
                                       const char *machine,
                                       virArch arch,
                                       virDomainVirtType virttype);

/* These are bit flags: */
typedef enum {
    BHYVE_GRUB_CAP_CONSDEV = 1,
} virBhyveGrubCapsFlags;

typedef enum {
    BHYVE_CAP_RTC_UTC,
    BHYVE_CAP_AHCI32SLOT,
    BHYVE_CAP_NET_E1000,
    BHYVE_CAP_LPC_BOOTROM,
    BHYVE_CAP_FBUF,
    BHYVE_CAP_XHCI,
    BHYVE_CAP_CPUTOPOLOGY,
    BHYVE_CAP_SOUND_HDA,
    BHYVE_CAP_VNC_PASSWORD,
    BHYVE_CAP_VIRTIO_9P,
    BHYVE_CAP_VIRTIO_RND,
    BHYVE_CAP_NVME,
    BHYVE_CAP_ACPI,
    BHYVE_CAP_NUMA,
    BHYVE_CAP_RCTL,
    BHYVE_CAP_MONITOR,
    BHYVE_CAP_GET_VMPID,
    BHYVE_CAP_LPC_TPM,

    BHYVE_CAP_LAST,
} virBhyveCapsFlags;

void virBhyveCapsSet(virBitmap *caps,
                     virBhyveCapsFlags flag) ATTRIBUTE_NONNULL(1);
void virBhyveCapsClear(virBitmap *caps,
                       virBhyveCapsFlags flag) ATTRIBUTE_NONNULL(1);
bool virBhyveCapsGet(virBitmap *caps,
                     virBhyveCapsFlags flag);

int virBhyveProbeGrubCaps(virBhyveGrubCapsFlags *caps);
int virBhyveProbeCaps(virBitmap **caps);
