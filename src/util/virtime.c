/*
 * virtime.c: Time handling functions
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 *
 * The intent is that this file provides a set of time APIs which
 * are async signal safe, to allow use in between fork/exec eg by
 * the logging code.
 *
 * The reality is that wsnprintf is technically unsafe. We ought
 * to roll out our int -> str conversions to avoid this.
 *
 * We do *not* use regular libvirt error APIs for most of the code,
 * since those are not async signal safe, and we dont want logging
 * APIs generating timestamps to blow away real errors
 */

#include <config.h>

#include <stdio.h>
#include <sys/time.h>

#include "virtime.h"
#include "viralloc.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/* We prefer clock_gettime if available because that is officially
 * async signal safe according to POSIX. Many platforms lack it
 * though, so fallback to gettimeofday everywhere else
 */

/**
 * virTimeMillisNowRaw:
 * @now: filled with current time in milliseconds
 *
 * Retrieves the current system time, in milliseconds since the
 * epoch
 *
 * Returns 0 on success, -1 on error with errno set
 */
int virTimeMillisNowRaw(unsigned long long *now)
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        return -1;

    *now = (ts.tv_sec * 1000ull) + (ts.tv_nsec / (1000ull * 1000ull));
#else
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0)
        return -1;

    *now = (tv.tv_sec * 1000ull) + (tv.tv_usec / 1000ull);
#endif

    return 0;
}


/**
 * virTimeFieldsNowRaw:
 * @fields: filled with current time fields
 *
 * Retrieves the current time, in broken-down field format.
 * The time is always in UTC.
 *
 * Returns 0 on success, -1 on error with errno set
 */
int virTimeFieldsNowRaw(struct tm *fields)
{
    unsigned long long now;

    if (virTimeMillisNowRaw(&now) < 0)
        return -1;

    virTimeFieldsThen(now, fields);

    return 0;
}


#define SECS_PER_HOUR   (60 * 60)
#define SECS_PER_DAY    (SECS_PER_HOUR * 24)
#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

static const unsigned short int mon_yday[2][13] = {
    /* Normal years.  */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* Leap years.  */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

#define is_leap_year(y) \
    ((y) % 4 == 0 && ((y) % 100 != 0 || (y) % 400 == 0))

/**
 * virTimeFieldsThen:
 * @when: the time to convert in milliseconds
 * @fields: filled with time @when fields
 *
 * Converts the timestamp @when into broken-down field format.
 * Time time is always in UTC
 *
 */
void virTimeFieldsThen(unsigned long long when, struct tm *fields)
{
    /* This code is taken from GLibC under terms of LGPLv2+ */
    /* Remove the 'offset' or GMT manipulation since we don't care. See
     * commit id '3ec12898' comments regarding localtime.
     */
    long int days, rem, y;
    const unsigned short int *ip;
    unsigned long long whenSecs = when / 1000ull;

    days = whenSecs / SECS_PER_DAY;
    rem = whenSecs % SECS_PER_DAY;

    fields->tm_hour = rem / SECS_PER_HOUR;
    rem %= SECS_PER_HOUR;
    fields->tm_min = rem / 60;
    fields->tm_sec = rem % 60;
    /* January 1, 1970 was a Thursday.  */
    fields->tm_wday = (4 + days) % 7;
    if (fields->tm_wday < 0)
        fields->tm_wday += 7;
    y = 1970;

    while (days < 0 || days >= (is_leap_year(y) ? 366 : 365)) {
        /* Guess a corrected year, assuming 365 days per year.  */
        long int yg = y + days / 365 - (days % 365 < 0);

      /* Adjust DAYS and Y to match the guessed year.  */
      days -= ((yg - y) * 365
               + LEAPS_THRU_END_OF(yg - 1)
               - LEAPS_THRU_END_OF(y - 1));
      y = yg;
    }
    fields->tm_year = y - 1900;

    fields->tm_yday = days;
    ip = mon_yday[is_leap_year(y)];
    for (y = 11; days < (long int) ip[y]; --y)
        continue;
    days -= ip[y];
    fields->tm_mon = y;
    fields->tm_mday = days + 1;
}


/**
 * virTimeStringNowRaw:
 * @buf: a buffer at least VIR_TIME_STRING_BUFLEN in length
 *
 * Initializes @buf to contain a formatted timestamp
 * corresponding to the current time.
 *
 * Returns 0 on success, -1 on error
 */
int virTimeStringNowRaw(char *buf)
{
    unsigned long long now;

    if (virTimeMillisNowRaw(&now) < 0)
        return -1;

    return virTimeStringThenRaw(now, buf);
}


/**
 * virTimeStringThenRaw:
 * @when: the time to format in milliseconds
 * @buf: a buffer at least VIR_TIME_STRING_BUFLEN in length
 *
 * Initializes @buf to contain a formatted timestamp
 * corresponding to the time @when.
 *
 * Returns 0 on success, -1 on error
 */
int virTimeStringThenRaw(unsigned long long when, char *buf)
{
    struct tm fields;

    virTimeFieldsThen(when, &fields);

    fields.tm_year += 1900;
    fields.tm_mon += 1;

    if (snprintf(buf, VIR_TIME_STRING_BUFLEN,
                 "%4d-%02d-%02d %02d:%02d:%02d.%03d+0000",
                 fields.tm_year, fields.tm_mon, fields.tm_mday,
                 fields.tm_hour, fields.tm_min, fields.tm_sec,
                 (int) (when % 1000)) >= VIR_TIME_STRING_BUFLEN) {
        errno = ERANGE;
        return -1;
    }

    return 0;
}


/**
 * virTimeMillisNow:
 * @now: filled with current time in milliseconds
 *
 * Retrieves the current system time, in milliseconds since the
 * epoch
 *
 * Returns 0 on success, -1 on error with error reported
 */
int virTimeMillisNow(unsigned long long *now)
{
    if (virTimeMillisNowRaw(now) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get current time"));
        return -1;
    }
    return 0;
}


/**
 * virTimeFieldsNowRaw:
 * @fields: filled with current time fields
 *
 * Retrieves the current time, in broken-down field format.
 * The time is always in UTC.
 *
 * Returns 0 on success, -1 on error with errno reported
 */
int virTimeFieldsNow(struct tm *fields)
{
    unsigned long long now;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    virTimeFieldsThen(now, fields);
    return 0;
}


/**
 * virTimeStringNow:
 *
 * Creates a string containing a formatted timestamp
 * corresponding to the current time.
 *
 * This function is not async signal safe
 *
 * Returns a formatted allocated string, or NULL on error
 */
char *virTimeStringNow(void)
{
    char *ret;

    if (VIR_ALLOC_N(ret, VIR_TIME_STRING_BUFLEN) < 0)
        return NULL;

    if (virTimeStringNowRaw(ret) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to format time"));
        VIR_FREE(ret);
        return NULL;
    }

    return ret;
}


/**
 * virTimeStringThen:
 * @when: the time to format in milliseconds
 *
 * Creates a string containing a formatted timestamp
 * corresponding to the time @when.
 *
 * This function is not async signal safe
 *
 * Returns a formatted allocated string, or NULL on error
 */
char *virTimeStringThen(unsigned long long when)
{
    char *ret;

    if (VIR_ALLOC_N(ret, VIR_TIME_STRING_BUFLEN) < 0)
        return NULL;

    if (virTimeStringThenRaw(when, ret) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to format time"));
        VIR_FREE(ret);
        return NULL;
    }

    return ret;
}

/**
 * virTimeLocalOffsetFromUTC:
 *
 * This function is threadsafe, but is *not* async signal safe (due to
 * gmtime_r() and mktime()).
 *
 * @offset: pointer to time_t that will be set to the difference
 *          between localtime and UTC in seconds (east of UTC is a
 *          positive number, and west of UTC is a negative number.
 *
 * Returns 0 on success, -1 on error with error reported
 */
int
virTimeLocalOffsetFromUTC(long *offset)
{
    struct tm gmtimeinfo;
    time_t current, utc;

    /* time() gives seconds since Epoch in current timezone */
    if ((current = time(NULL)) == (time_t)-1) {
        virReportSystemError(errno, "%s",
                             _("failed to get current system time"));
        return -1;
    }

    /* treat current as if it were in UTC */
    if (!gmtime_r(&current, &gmtimeinfo)) {
        virReportSystemError(errno, "%s",
                             _("gmtime_r failed"));
        return -1;
    }

    /* tell mktime to figure out itself whether or not DST is in effect */
    gmtimeinfo.tm_isdst = -1;

    /* mktime() also obeys current timezone rules */
    if ((utc = mktime(&gmtimeinfo)) == (time_t)-1) {
        virReportSystemError(errno, "%s",
                             _("mktime failed"));
        return -1;
    }

    *offset = current - utc;
    return 0;
}
