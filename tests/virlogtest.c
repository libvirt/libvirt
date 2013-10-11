/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#include <config.h>

#include "testutils.h"

#include "virlog.h"

struct testLogMatchData {
    const char *str;
    bool res;
};

static int
testLogMatch(const void *opaque)
{
    const struct testLogMatchData *data = opaque;

    bool got = virLogProbablyLogMessage(data->str);
    if (got != data->res) {
        fprintf(stderr, "Expected '%d' but got '%d' for '%s'\n",
                data->res, got, data->str);
        return -1;
    }
    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#define TEST_LOG_MATCH(str, res)                                        \
    do {                                                                \
        struct testLogMatchData data = {                                \
            str, res                                                    \
        };                                                              \
        if (virtTestRun("testLogMatch " # str, testLogMatch, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    TEST_LOG_MATCH("2013-10-11 15:43:43.866+0000: 28302: info : libvirt version: 1.1.3", true);

    TEST_LOG_MATCH("libvirt:  error : cannot execute binary /usr/libexec/libvirt_lxc: No such file or directory", false);

    return ret;
}

VIRT_TEST_MAIN(mymain)
