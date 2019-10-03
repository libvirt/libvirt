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
#ifdef WITH_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#endif

#include "virrandom.h"
#include "virthread.h"
#include "virutil.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.random");

#define RANDOM_SOURCE "/dev/urandom"

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
    if ((max & (max - 1)) == 0)
        return virRandomBits(__builtin_ffs(max) - 1);

    double val = virRandom();
    return val * max;
}


/**
 * virRandomBytes
 * @buf: Pointer to location to store bytes
 * @buflen: Number of bytes to store
 *
 * Generate a stream of random bytes from RANDOM_SOURCE
 * into @buf of size @buflen
 *
 * Returns 0 on success or -1 (with error reported)
 */
int
virRandomBytes(unsigned char *buf,
               size_t buflen)
{
#if WITH_GNUTLS
    int rv;

    /* Generate the byte stream using gnutls_rnd() if possible */
    if ((rv = gnutls_rnd(GNUTLS_RND_RANDOM, buf, buflen)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to generate byte stream: %s"),
                       gnutls_strerror(rv));
        return -1;
    }

#else /* !WITH_GNUTLS */

    int fd;

    if ((fd = open(RANDOM_SOURCE, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("unable to open %s"),
                             RANDOM_SOURCE);
        return -1;
    }

    while (buflen > 0) {
        ssize_t n;

        if ((n = saferead(fd, buf, buflen)) <= 0) {
            virReportSystemError(errno,
                                 _("unable to read from %s"),
                                 RANDOM_SOURCE);
            VIR_FORCE_CLOSE(fd);
            return n < 0 ? -errno : -ENODATA;
        }

        buf += n;
        buflen -= n;
    }

    VIR_FORCE_CLOSE(fd);
#endif /* !WITH_GNUTLS */

    return 0;
}


#define QUMRANET_OUI "001a4a"
#define VMWARE_OUI "000569"
#define MICROSOFT_OUI "0050f2"
#define XEN_OUI "00163e"


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

    if (STREQ(virt_type, "QEMU")) {
        oui = QUMRANET_OUI;
    } else if (STREQ(virt_type, "Xen") ||
               STREQ(virt_type, "xenlight")) {
        oui = XEN_OUI;
    } else if (STREQ(virt_type, "ESX") ||
               STREQ(virt_type, "VMWARE")) {
        oui = VMWARE_OUI;
    } else if (STREQ(virt_type, "HYPER-V")) {
        oui = MICROSOFT_OUI;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unsupported virt type"));
        return -1;
    }

    if (virAsprintf(wwn, "5" "%s%09llx", oui,
                    (unsigned long long)virRandomBits(36)) < 0)
        return -1;
    return 0;
}
