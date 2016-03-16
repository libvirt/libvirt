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

struct testLogData {
    const char *str;
    bool pass;
};

static int
testLogMatch(const void *opaque)
{
    const struct testLogData *data = opaque;

    bool got = virLogProbablyLogMessage(data->str);
    if (got != data->pass) {
        VIR_TEST_DEBUG("Expected '%d' but got '%d' for '%s'\n",
                       data->pass, got, data->str);
        return -1;
    }
    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, test, str, pass)                                 \
    do {                                                                    \
        struct testLogData data = {                                         \
            str, pass                                                       \
        };                                                                  \
        if (virtTestRun(name, test, &data) < 0)                             \
            ret = -1;                                                       \
    } while (0)

#define TEST_LOG_MATCH_FAIL(str)                                            \
    DO_TEST_FULL("testLogMatch " # str, testLogMatch, str, false)
#define TEST_LOG_MATCH(str)                                                 \
    DO_TEST_FULL("testLogMatch " # str, testLogMatch, str, true)

    TEST_LOG_MATCH("2013-10-11 15:43:43.866+0000: 28302: info : libvirt version: 1.1.3");

    TEST_LOG_MATCH_FAIL("libvirt:  error : cannot execute binary /usr/libexec/libvirt_lxc: No such file or directory");

    return ret;
}

VIRT_TEST_MAIN(mymain)
