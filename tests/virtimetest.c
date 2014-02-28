/*
 * Copyright (C) 2011, 2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.timetest");

struct testTimeFieldsData {
    unsigned long long when;
    struct tm fields;
};

static int testTimeFields(const void *args)
{
    const struct testTimeFieldsData *data = args;
    struct tm actual;

    if (virTimeFieldsThen(data->when, &actual) < 0)
        return -1;

#define COMPARE(field)                                          \
    do {                                                        \
        if (data->fields.field != actual.field) {               \
            VIR_DEBUG("Expect " #field " %d got %d",            \
                      data->fields.field, actual.field);        \
            return -1;                                          \
        }                                                       \
    } while (0)

    /* tm_year value 0 is based off epoch 1900 */
    actual.tm_year += 1900;
    /* tm_mon is range 0-11, but we want 1-12 */
    actual.tm_mon += 1;

    COMPARE(tm_year);
    COMPARE(tm_mon);
    COMPARE(tm_mday);
    COMPARE(tm_hour);
    COMPARE(tm_min);
    COMPARE(tm_sec);

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

#define TEST_FIELDS(ts, year, mon, day, hour, min, sec)            \
    do {                                                             \
        struct testTimeFieldsData data = {                           \
            .when = ts,                                              \
            .fields = {                                              \
                .tm_year = year,                                     \
                .tm_mon = mon,                                       \
                .tm_mday = day,                                      \
                .tm_hour = hour,                                     \
                .tm_min = min,                                       \
                .tm_sec = sec,                                       \
                .tm_wday = 0,                                        \
                .tm_yday = 0,                                        \
                .tm_isdst = 0,                                       \
            },                                                       \
        };                                                           \
        if (virtTestRun("Test fields " #ts " " #year " ", testTimeFields, &data) < 0) \
            ret = -1;                                                \
    } while (0)

    TEST_FIELDS(0ull,           1970,  1,  1,  0,  0,  0);
    TEST_FIELDS(5000ull,        1970,  1,  1,  0,  0,  5);
    TEST_FIELDS(3605000ull,     1970,  1,  1,  1,  0,  5);
    TEST_FIELDS(86405000ull,    1970,  1,  2,  0,  0,  5);
    TEST_FIELDS(31536000000ull, 1971,  1,  1,  0,  0,  0);

    TEST_FIELDS(30866399000ull,  1970, 12, 24,  5, 59, 59);
    TEST_FIELDS(123465599000ull, 1973, 11, 29, 23, 59, 59);
    TEST_FIELDS(155001599000ull, 1974, 11, 29, 23, 59, 59);

    TEST_FIELDS(186537599000ull,  1975, 11, 29, 23, 59, 59);
    TEST_FIELDS(344390399000ull,  1980, 11, 29, 23, 59, 59);
    TEST_FIELDS(1203161493000ull, 2008,  2, 16, 11, 31, 33);
    TEST_FIELDS(1234567890000ull, 2009,  2, 13, 23, 31, 30);

    TEST_FIELDS(1322524800000ull, 2011, 11, 29,  0,  0,  0);
    TEST_FIELDS(1322611199000ull, 2011, 11, 29, 23, 59, 59);

    TEST_FIELDS(2147483648000ull, 2038,  1, 19,  3, 14,  8);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
