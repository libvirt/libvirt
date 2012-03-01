/*
 * Copyright (C) 2012 Red Hat, Inc.
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
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <inttypes.h>

#include "virrandom.h"
#include "threads.h"
#include "count-one-bits.h"
#include "util.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virRandomError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

static char randomState[128];
static struct random_data randomData;
static virMutex randomLock;


int virRandomInitialize(uint32_t seed)
{
    if (virMutexInit(&randomLock) < 0)
        return -1;

    if (initstate_r(seed,
                    randomState,
                    sizeof(randomState),
                    &randomData) < 0)
        return -1;

    return 0;
}

/* The algorithm of virRandomBits requires that RAND_MAX == 2^n-1 for
 * some n; gnulib's random_r meets this property. */
verify(((RAND_MAX + 1U) & RAND_MAX) == 0);

/**
 * virRandomBits:
 * @nbits: Number of bits of randommess required
 *
 * Generate an evenly distributed random number between [0,2^nbits), where
 * @nbits must be in the range (0,64].
 *
 * Return: a random number with @nbits entropy
 */
uint64_t virRandomBits(int nbits)
{
    int bits_per_iter = count_one_bits(RAND_MAX);
    uint64_t ret = 0;
    int32_t bits;

    virMutexLock(&randomLock);

    while (nbits > bits_per_iter) {
        random_r(&randomData, &bits);
        ret = (ret << bits_per_iter) | (bits & RAND_MAX);
        nbits -= bits_per_iter;
    }

    random_r(&randomData, &bits);
    ret = (ret << nbits) | (bits & ((1 << nbits) - 1));

    virMutexUnlock(&randomLock);
    return ret;
}

#define QUMRANET_OUI "001a4a"
#define VMWARE_OUI "000569"
#define MICROSOFT_OUI "0050f2"
#define XEN_OUI "00163e"

int
virRandomGenerateWWN(char **wwn,
                     const char *virt_type) {
    const char *oui = NULL;

    if (!virt_type) {
        virRandomError(VIR_ERR_INVALID_ARG, "%s",
                       _("argument virt_type must not be NULL"));
        return -1;
    }

    if (STREQ(virt_type, "QEMU")) {
        oui = QUMRANET_OUI;
    } else if (STREQ(virt_type, "Xen") ||
               STREQ(virt_type, "xenlight") ||
               STREQ(virt_type, "XenAPI")) {
        oui = XEN_OUI;
    } else if (STREQ(virt_type, "ESX") ||
               STREQ(virt_type, "VMWARE")) {
        oui = VMWARE_OUI;
    } else if (STREQ(virt_type, "HYPER-V")) {
        oui = MICROSOFT_OUI;
    } else {
        virRandomError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unsupported virt type"));
        return -1;
    }

    if (virAsprintf(wwn, "5" "%s%09llx", oui,
                    (unsigned long long)virRandomBits(36)) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}
