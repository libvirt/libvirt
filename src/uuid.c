/*
 * Copyright (C) 2007, 2008 Red Hat, Inc.
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

#define qemudLog(level, msg...) fprintf(stderr, msg)

#ifndef ENODATA
#define ENODATA EIO
#endif

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
            close(fd);
            return n < 0 ? errno : ENODATA;
        }

        buf += n;
        buflen -= n;
    }

    close(fd);

    return 0;
}

static int
virUUIDGeneratePseudoRandomBytes(unsigned char *buf,
                                 int buflen)
{
    srand(time(NULL));
    while (buflen > 0) {
        *buf = (int) (255.0 * (rand() / (double) RAND_MAX));
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
        return(-1);

    if ((err = virUUIDGenerateRandomBytes(uuid, VIR_UUID_BUFLEN)))
        qemudLog(QEMUD_WARN,
                 _("Falling back to pseudorandom UUID,"
                   " failed to generate random bytes: %s"), strerror(err));

    return virUUIDGeneratePseudoRandomBytes(uuid, VIR_UUID_BUFLEN);
}

/* Convert C from hexadecimal character to integer.  */
static int
hextobin (unsigned char c)
{
  switch (c)
    {
    default: return c - '0';
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
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

    if ((uuidstr == NULL) || (uuid == NULL))
        return(-1);

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs as long as there is 32 of them in the end.
     */
    cur = uuidstr;
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
        uuid[i] = hextobin(*cur);
        uuid[i] *= 16;
        cur++;
        if (*cur == 0)
            goto error;
        if (!c_isxdigit(*cur))
            goto error;
        uuid[i] += hextobin(*cur);
        i++;
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
