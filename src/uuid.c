/*
 * Copyright (C) 2007 Red Hat, Inc.
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

#include "config.h"

#include "uuid.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "internal.h"

#define qemudLog(level, msg...) fprintf(stderr, msg)

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
 * @uuid: array of VIR_UUID_RAW_LEN bytes to store the new UUID
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

    if ((err = virUUIDGenerateRandomBytes(uuid, VIR_UUID_RAW_LEN)))
        qemudLog(QEMUD_WARN,
                 "Falling back to pseudorandom UUID, "
                 "failed to generate random bytes: %s", strerror(err));

    return virUUIDGeneratePseudoRandomBytes(uuid, VIR_UUID_RAW_LEN);
}

/**
 * virUUIDParse:
 * @uuid: zero terminated string representation of the UUID
 * @rawuuid: array of VIR_UUID_RAW_LEN bytes to store the raw UUID
 *
 * Parses the external string representation, allowing spaces and '-'
 * character in the sequence, and storing the result as a raw UUID
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
virUUIDParse(const char *uuid, unsigned char *rawuuid) {
    const char *cur;
    int i;

    if ((uuid == NULL) || (rawuuid == NULL))
        return(-1);

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs as long as there is 32 of them in the end.
     */
    cur = uuid;
    for (i = 0;i < 16;) {
        rawuuid[i] = 0;
        if (*cur == 0)
            goto error;
        if ((*cur == '-') || (*cur == ' ')) {
            cur++;
            continue;
        }
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] = *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] = *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] = *cur - 'A' + 10;
        else
            goto error;
        rawuuid[i] *= 16;
        cur++;
        if (*cur == 0)
            goto error;
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] += *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] += *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] += *cur - 'A' + 10;
        else
            goto error;
        i++;
        cur++;
    }

    return 0;

 error:
    return -1;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */

