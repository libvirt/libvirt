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

    virTimeFieldsThen(data->when, &actual);

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


typedef struct {
    const char *zone;
    long offset;
} testTimeLocalOffsetData;

static int
testTimeLocalOffset(const void *args)
{
    const testTimeLocalOffsetData *data = args;
    long actual;

    if (setenv("TZ", data->zone, 1) < 0) {
        perror("setenv");
        return -1;
    }
    tzset();

    if (virTimeLocalOffsetFromUTC(&actual) < 0)
        return -1;

    if (data->offset != actual) {
        VIR_DEBUG("Expect Offset %ld got %ld",
                  data->offset, actual);
        return -1;
    }
    return 0;
}


/* return true if the date is Jan 1 or Dec 31 (localtime) */
static bool
isNearYearEnd(void)
{
    time_t current = time(NULL);
    struct tm timeinfo;

    if (current == (time_t)-1) {
        VIR_DEBUG("time() failed");
        return false;
    }
    if (!localtime_r(&current, &timeinfo)) {
        VIR_DEBUG("localtime_r() failed");
        return false;
    }

    return (timeinfo.tm_mon == 0 && timeinfo.tm_mday == 1) ||
            (timeinfo.tm_mon == 11 && timeinfo.tm_mday == 31);
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

#define TEST_FIELDS(ts, year, mon, day, hour, min, sec)                              \
    do {                                                                             \
        struct testTimeFieldsData data = {                                           \
            .when = ts,                                                              \
            .fields = {                                                              \
                .tm_year = year,                                                     \
                .tm_mon = mon,                                                       \
                .tm_mday = day,                                                      \
                .tm_hour = hour,                                                     \
                .tm_min = min,                                                       \
                .tm_sec = sec,                                                       \
                .tm_wday = 0,                                                        \
                .tm_yday = 0,                                                        \
                .tm_isdst = 0,                                                       \
            },                                                                       \
        };                                                                           \
        if (virTestRun("Test fields " #ts " " #year " ", testTimeFields, &data) < 0) \
            ret = -1;                                                                \
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

#define TEST_LOCALOFFSET(tz, off)                         \
    do {                                                  \
       testTimeLocalOffsetData data = {                   \
           .zone =  tz,                                   \
           .offset = off,                                 \
        };                                                \
        if (virTestRun("Test localtime offset for " #tz,  \
                       testTimeLocalOffset, &data) < 0)   \
            ret = -1;                                     \
    } while (0)

    TEST_LOCALOFFSET("VIR00:30", -30 * 60);
    TEST_LOCALOFFSET("VIR01:30", -90 * 60);
    TEST_LOCALOFFSET("VIR05:00", (-5 * 60) * 60);
    TEST_LOCALOFFSET("UTC", 0);
    TEST_LOCALOFFSET("VIR-00:30", 30 * 60);
    TEST_LOCALOFFSET("VIR-01:30", 90 * 60);

    /* test DST processing with timezones that always
     * have DST in effect; what's more, cover a zone with
     * with an unusual DST different than a usual one hour
     */
    TEST_LOCALOFFSET("VIR-00:30VID,0/00:00:00,365/23:59:59",
                     ((1 * 60) + 30) * 60);
    TEST_LOCALOFFSET("VIR-02:30VID,0/00:00:00,365/23:59:59",
                     ((3 * 60) + 30) * 60);
    TEST_LOCALOFFSET("VIR-02:30VID-04:30,0/00:00:00,365/23:59:59",
                     ((4 * 60) + 30) * 60);
    TEST_LOCALOFFSET("VIR-12:00VID-13:00,0/00:00:00,365/23:59:59",
                     ((13 * 60) +  0) * 60);

    if (!isNearYearEnd()) {
        /* experiments have shown that the following tests will fail
         * during certain hours of Dec 31 or Jan 1 (depending on the
         * TZ setting in the shell running the test, but in general
         * for a period that apparently starts at 00:00:00 UTC Jan 1
         * and continues for 1 - 2 hours). We've determined this is
         * due to our inability to specify a timezone with DST on/off
         * settings that make it truly *always* on DST - i.e. it is a
         * failing of the test data, *not* of the function we are
         * testing. So to test as much as possible, we still run these
         * tests, except on Dec 31 and Jan 1.
         */

        TEST_LOCALOFFSET("VIR02:45VID00:45,0/00:00:00,365/23:59:59",
                         -45 * 60);
        TEST_LOCALOFFSET("VIR05:00VID04:00,0/00:00:00,365/23:59:59",
                         ((-4 * 60) +  0) * 60);
        TEST_LOCALOFFSET("VIR11:00VID10:00,0/00:00:00,365/23:59:59",
                         ((-10 * 60) +  0) * 60);
    }

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
