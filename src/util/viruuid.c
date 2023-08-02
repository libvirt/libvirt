/*
 * viruuid.c: helper APIs for dealing with UUIDs
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

#include "viruuid.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "virlog.h"
#include "virfile.h"
#include "virrandom.h"

VIR_LOG_INIT("util.uuid");

static unsigned char host_uuid[VIR_UUID_BUFLEN];

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
    if (uuid == NULL)
        return -1;

    if (virRandomBytes(uuid, VIR_UUID_BUFLEN) < 0)
        return -1;

    /*
     * Make UUID RFC 4122 compliant. Following form will be used:
     *
     * xxxxxxxx-xxxx-Axxx-Bxxx-xxxxxxxxxxxx
     *
     * where
     * A is version defined in 4.1.3 of RFC
     *  Msb0  Msb1  Msb2  Msb3   Version  Description
     *   0     1     0     0        4     The randomly or pseudo-
     *                                    randomly generated version
     *                                    specified in this document.
     *
     * B is variant defined in 4.1.1 of RFC
     *  Msb0  Msb1  Msb2  Description
     *   1     0     x    The variant specified in this document.
     */
    uuid[6] = (uuid[6] & 0x0F) | (4 << 4);
    uuid[8] = (uuid[8] & 0x3F) | (2 << 6);

    return 0;
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
virUUIDParse(const char *uuidstr, unsigned char *uuid)
{
    const char *cur;
    size_t i;

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs, and surrounding whitespace, as long as there are exactly
     * 32 hexadecimal digits the end.
     */
    cur = uuidstr;
    while (g_ascii_isspace(*cur))
        cur++;

    for (i = 0; i < VIR_UUID_BUFLEN;) {
        int val;
        uuid[i] = 0;
        if (*cur == 0)
            return -1;
        if ((*cur == '-') || (*cur == ' ')) {
            cur++;
            continue;
        }
        if ((val = g_ascii_xdigit_value(*cur)) < 0)
            return -1;
        uuid[i] = 16 * val;
        cur++;
        if (*cur == 0)
            return -1;
        if ((val = g_ascii_xdigit_value(*cur)) < 0)
            return -1;
        uuid[i] += val;
        i++;
        cur++;
    }

    while (*cur) {
        if (!g_ascii_isspace(*cur))
            return -1;
        cur++;
    }

    return 0;
}

/**
 * virUUIDFormat:
 * @uuid: array of VIR_UUID_BUFLEN bytes to store the raw UUID
 * @uuidstr: array of VIR_UUID_STRING_BUFLEN bytes to store the
 * string representation of the UUID in. The resulting string
 * will be NULL terminated.
 *
 * Converts the raw UUID into printable format, with embedded '-'
 *
 * Returns a pointer to the resulting character string.
 */
const char *
virUUIDFormat(const unsigned char *uuid, char *uuidstr)
{
    g_snprintf(uuidstr, VIR_UUID_STRING_BUFLEN,
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               uuid[0], uuid[1], uuid[2], uuid[3],
               uuid[4], uuid[5], uuid[6], uuid[7],
               uuid[8], uuid[9], uuid[10], uuid[11],
               uuid[12], uuid[13], uuid[14], uuid[15]);
    uuidstr[VIR_UUID_STRING_BUFLEN-1] = '\0';
    return uuidstr;
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
bool
virUUIDIsValid(const unsigned char *uuid)
{
    size_t i;

    if (!uuid)
        return false;

    for (i = 1; i < VIR_UUID_BUFLEN; i++)
        if (uuid[i] != uuid[0])
            return true;

    return false;
}


static int
getDMISystemUUID(char *uuid, int len)
{
    size_t i = 0;
    const char *paths[] = {
        "/sys/devices/virtual/dmi/id/product_uuid",
        "/sys/class/dmi/id/product_uuid",
        NULL
    };

    while (paths[i]) {
        if (virFileReadBufQuiet(paths[i], uuid, len) == len - 1)
            return 0;
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

    if (virUUIDIsValid(host_uuid))
        return EEXIST;

    if (!uuid) {
        char dmiuuid[VIR_UUID_STRING_BUFLEN] = { 0 };

        if (!getDMISystemUUID(dmiuuid, sizeof(dmiuuid))) {
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
