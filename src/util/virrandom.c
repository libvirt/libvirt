/*
 * Copyright (C) 2012-2016 Red Hat, Inc.
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

#include <config.h>

#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "virrandom.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.random");

/**
 * virRandomBits:
 * @nbits: Number of bits of randomness required
 *
 * Generate an evenly distributed random number between [0,2^nbits), where
 * @nbits must be in the range (0,64].
 *
 * Return: a random number with @nbits entropy
 */
uint64_t virRandomBits(int nbits)
{
    uint64_t ret = 0;

    if (virRandomBytes((unsigned char *) &ret, sizeof(ret)) < 0) {
        /* You're already hosed, so this particular non-random value
         * isn't any worse.  */
        return 0;
    }

    if (nbits < 64)
        ret &= (1ULL << nbits) - 1;

    return ret;
}


/**
 * virRandom:
 *
 * Generate an evenly distributed random number between [0.0,1.0)
 *
 * Return: a random number with 48 bits of entropy
 */
double virRandom(void)
{
    uint64_t val = virRandomBits(48);

    return ldexp(val, -48);
}


/**
 * virRandomInt:
 * @max: upper limit
 *
 * Generate an evenly distributed random integer between [0, @max)
 *
 * Return: a random number between [0,@max)
 */
uint32_t virRandomInt(uint32_t max)
{
    if (VIR_IS_POW2(max))
        return virRandomBits(__builtin_ffs(max) - 1);

    return virRandom() * max;
}


/**
 * virRandomBytes
 * @buf: Pointer to location to store bytes
 * @buflen: Number of bytes to store
 *
 * Generate a stream of random bytes using gnutls_rnd()
 * into @buf of size @buflen
 *
 * Returns 0 on success or -1 (with error reported)
 */
int
virRandomBytes(unsigned char *buf,
               size_t buflen)
{
    int rv;

    if ((rv = gnutls_rnd(GNUTLS_RND_RANDOM, buf, buflen)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to generate byte stream: %1$s"),
                       gnutls_strerror(rv));
        return -1;
    }

    return 0;
}


#define QUMRANET_OUI "001a4a"
#define VMWARE_OUI "000569"
#define MICROSOFT_OUI "0050f2"
#define XEN_OUI "00163e"
#define TEST_DRIVER_OUI "100000"


int
virRandomGenerateWWN(char **wwn,
                     const char *virt_type)
{
    const char *oui = NULL;

    if (!virt_type) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("argument virt_type must not be NULL"));
        return -1;
    }

    /* In case of split daemon we don't really see the hypervisor
     * driver that just re-routed the nodedev driver API. There
     * might not be any hypervisor driver even. Yet, we have to
     * pick OUI. Pick "QEMU". */

    if (STREQ(virt_type, "QEMU") ||
        STREQ(virt_type, "nodedev")) {
        oui = QUMRANET_OUI;
    } else if (STREQ(virt_type, "Xen") ||
               STREQ(virt_type, "xenlight")) {
        oui = XEN_OUI;
    } else if (STREQ(virt_type, "ESX") ||
               STREQ(virt_type, "VMWARE")) {
        oui = VMWARE_OUI;
    } else if (STREQ(virt_type, "HYPER-V")) {
        oui = MICROSOFT_OUI;
    } else if (STREQ(virt_type, "TEST")) {
        oui = TEST_DRIVER_OUI;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unsupported virt type"));
        return -1;
    }

    *wwn = g_strdup_printf("5%s%09" PRIx64, oui, virRandomBits(36));
    return 0;
}

char *virRandomToken(size_t len)
{
    g_autofree unsigned char *data = g_new0(unsigned char, len);
    g_autofree char *token = g_new0(char, (len * 2) + 1);
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (virRandomBytes(data, len) < 0)
        return NULL;

    for (i = 0; i < len; i++) {
        token[(i*2)] = hex[data[i] & 0xf];
        token[(i*2)+1] = hex[(data[i] >> 4) & 0xf];
    }

    return g_steal_pointer(&token);
}
