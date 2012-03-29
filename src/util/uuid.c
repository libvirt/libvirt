/*
 * Copyright (C) 2007-2012 Red Hat, Inc.
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
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#include "uuid.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "c-ctype.h"
#include "internal.h"
#include "util.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "virfile.h"
#include "virrandom.h"

#ifndef ENODATA
# define ENODATA EIO
#endif

static unsigned char host_uuid[VIR_UUID_BUFLEN];

static int
virUUIDGenerateRandomBytes(unsigned char *buf,
                           int buflen)
{
    int fd;

    if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
        return errno;

    while (buflen > 0) {
        int n;

        if ((n = read(fd, buf, buflen)) <= 0) {
            if (errno == EINTR)
                continue;
            VIR_FORCE_CLOSE(fd);
            return n < 0 ? errno : ENODATA;
        }

        buf += n;
        buflen -= n;
    }

    VIR_FORCE_CLOSE(fd);

    return 0;
}

static int
virUUIDGeneratePseudoRandomBytes(unsigned char *buf,
                                 int buflen)
{
    while (buflen > 0) {
        *buf++ = virRandomBits(8);
        buflen--;
    }

    return 0;
}

/**
 * virUUIDGenerate:
 * @uuid: array of VIR_UUID_BUFLEN bytes to store the new UUID
 *
 * Generates a randomized unique identifier.
 *
 * Returns 0 in case of success and -1 in case of failure
 */
int
virUUIDGenerate(unsigned char *uuid)
{
    int err;

    if (uuid == NULL)
        return -1;

    if ((err = virUUIDGenerateRandomBytes(uuid, VIR_UUID_BUFLEN))) {
        char ebuf[1024];
        VIR_WARN("Falling back to pseudorandom UUID,"
                 " failed to generate random bytes: %s",
                 virStrerror(err, ebuf, sizeof(ebuf)));
        err = virUUIDGeneratePseudoRandomBytes(uuid, VIR_UUID_BUFLEN);
    }

    return err;
}

/**
 * virUUIDParse:
 * @uuidstr: zero terminated string representation of the UUID
 * @uuid: array of VIR_UUID_BUFLEN bytes to store the raw UUID
 *
 * Parses the external string representation, allowing spaces and '-'
 * character in the sequence, and storing the result as a raw UUID
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
virUUIDParse(const char *uuidstr, unsigned char *uuid) {
    const char *cur;
    int i;

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs, and surrounding whitespace, as long as there are exactly
     * 32 hexadecimal digits the end.
     */
    cur = uuidstr;
    while (c_isspace(*cur))
        cur++;

    for (i = 0;i < VIR_UUID_BUFLEN;) {
        uuid[i] = 0;
        if (*cur == 0)
            goto error;
        if ((*cur == '-') || (*cur == ' ')) {
            cur++;
            continue;
        }
        if (!c_isxdigit(*cur))
            goto error;
        uuid[i] = virHexToBin(*cur);
        uuid[i] *= 16;
        cur++;
        if (*cur == 0)
            goto error;
        if (!c_isxdigit(*cur))
            goto error;
        uuid[i] += virHexToBin(*cur);
        i++;
        cur++;
    }

    while (*cur) {
        if (!c_isspace(*cur))
            goto error;
        cur++;
    }

    return 0;

 error:
    return -1;
}

/**
 * virUUIDFormat:
 * @uuid: array of VIR_UUID_RAW_LEN bytes to store the raw UUID
 * @uuidstr: array of VIR_UUID_STRING_BUFLEN bytes to store the
 * string representation of the UUID in. The resulting string
 * will be NULL terminated.
 *
 * Converts the raw UUID into printable format, with embedded '-'
 *
 * Returns 0 in case of success and -1 in case of error.
 */
void virUUIDFormat(const unsigned char *uuid, char *uuidstr)
{
    snprintf(uuidstr, VIR_UUID_STRING_BUFLEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
    uuidstr[VIR_UUID_STRING_BUFLEN-1] = '\0';
}



/**
 * virUUIDIsValid
 *
 * @uuid: The UUID to test
 *
 * Do some basic tests to check whether the given UUID is
 * valid as a host UUID.
 * Basic tests:
 *  - Not all of the digits may be equal
 */
int
virUUIDIsValid(unsigned char *uuid)
{
    unsigned int i, ctr = 1;
    unsigned char c;

    if (!uuid)
        return 0;

    c = uuid[0];

    for (i = 1; i < VIR_UUID_BUFLEN; i++)
        if (uuid[i] == c)
            ctr++;

    return ctr != VIR_UUID_BUFLEN;
}

static int
getDMISystemUUID(char *uuid, int len)
{
    unsigned int i = 0;
    const char *paths[] = {
        "/sys/devices/virtual/dmi/id/product_uuid",
        "/sys/class/dmi/id/product_uuid",
        NULL
    };

    while (paths[i]) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            if (saferead(fd, uuid, len) == len) {
                VIR_FORCE_CLOSE(fd);
                return 0;
            }
            VIR_FORCE_CLOSE(fd);
        }
        i++;
    }

    return -1;
}


/**
 * setHostUUID
 *
 * @host_uuid: UUID that the host is supposed to have
 *
 * Set the UUID of the host if it hasn't been set, yet
 * Returns 0 in case of success, an error code in case of error.
 */
int
virSetHostUUIDStr(const char *uuid)
{
    int rc;
    char dmiuuid[VIR_UUID_STRING_BUFLEN];

    if (virUUIDIsValid(host_uuid))
        return EEXIST;

    if (!uuid) {
        memset(dmiuuid, 0, sizeof(dmiuuid));
        if (!getDMISystemUUID(dmiuuid, sizeof(dmiuuid) - 1)) {
            if (!virUUIDParse(dmiuuid, host_uuid))
                return 0;
        }

        if (!virUUIDIsValid(host_uuid))
            return virUUIDGenerate(host_uuid);
    } else {
        rc = virUUIDParse(uuid, host_uuid);
        if (rc)
            return rc;
        if (!virUUIDIsValid(host_uuid))
            return EINVAL;
    }

    return 0;
}

/**
 * getHostUUID:
 *
 * @host_uuid: memory to store the host_uuid into
 *
 * Get the UUID of the host. Returns 0 in case of success,
 * an error code otherwise.
 * Returns 0 in case of success, an error code in case of error.
 */
int virGetHostUUID(unsigned char *uuid)
{
    int ret = 0;

    if (!virUUIDIsValid(host_uuid))
        ret = virSetHostUUIDStr(NULL);

    memcpy(uuid, host_uuid, sizeof(host_uuid));

    return ret;
}
