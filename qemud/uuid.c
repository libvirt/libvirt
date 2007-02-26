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

#include "protocol.h"
#include "internal.h"

static int
qemudGenerateRandomBytes(unsigned char *buf,
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
qemudGeneratePseudoRandomBytes(unsigned char *buf,
                               int buflen)
{
    srand(time(NULL));
    while (buflen > 0) {
        *buf = (int) (255.0 * (rand() / (double) RAND_MAX));
        buflen--;
    }

    return 0;
}

int
qemudGenerateUUID(unsigned char *uuid)
{
    int err;

    if ((err = qemudGenerateRandomBytes(uuid, QEMUD_UUID_RAW_LEN)))
        qemudLog(QEMUD_WARN,
                 "Falling back to pseudorandom UUID, "
                 "failed to generate random bytes: %s", strerror(err));

    return qemudGeneratePseudoRandomBytes(uuid, QEMUD_UUID_RAW_LEN);
}

int
qemudParseUUID(const char *uuid, unsigned char *rawuuid) {
    const char *cur;
    int i;

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

