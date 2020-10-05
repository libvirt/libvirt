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

#include <unistd.h>
#include <sys/time.h>

#include "virtime.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.time");

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
    *now = g_get_real_time() / 1000;
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

    if (g_snprintf(buf, VIR_TIME_STRING_BUFLEN,
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
 * virTimeFieldsNow:
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

    ret = g_new0(char, VIR_TIME_STRING_BUFLEN);

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

    ret = g_new0(char, VIR_TIME_STRING_BUFLEN);

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
 * This function is threadsafe, but is *not* async signal safe
 * due to use of GLib APIs.
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
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    GTimeSpan diff = g_date_time_get_utc_offset(now);

    /* GTimeSpan measures microseconds, we want seconds */
    *offset = diff / 1000000;
    return 0;
}

/**
 * virTimeBackOffStart:
 * @var: Timeout variable (with type virTimeBackOffVar).
 * @first: Initial time to wait (milliseconds).
 * @timeout: Timeout (milliseconds).
 *
 * Initialize the timeout variable @var and start the timer running.
 *
 * Returns 0 on success, -1 on error and raises a libvirt error.
 */
int
virTimeBackOffStart(virTimeBackOffVar *var,
                    unsigned long long first, unsigned long long timeout)
{
    if (virTimeMillisNow(&var->start_t) < 0)
        return -1;

    var->next = first;
    var->limit_t = var->start_t + timeout;
    return 0;
}


#define VIR_TIME_BACKOFF_CAP 1000

/**
 * virTimeBackOffWait
 * @var: Timeout variable (with type virTimeBackOffVar *).
 *
 * You must initialize @var first by calling the following function,
 * which also starts the timer:
 *
 * if (virTimeBackOffStart(&var, first, timeout) < 0) {
 *   // handle errors
 * }
 *
 * Then you use a while loop:
 *
 * while (virTimeBackOffWait(&var)) {
 *   //...
 * }
 *
 * The while loop that runs the body of the code repeatedly, with an
 * exponential backoff.  It first waits for first milliseconds, then
 * runs the body, then waits for 2*first ms, then runs the body again.
 * Then 4*first ms, and so on, up until wait time would reach
 * VIR_TIME_BACK_OFF_CAP (whole second). Then it switches to constant
 * waiting time of VIR_TIME_BACK_OFF_CAP.
 *
 * When timeout milliseconds is reached, the while loop ends.
 *
 * The body should use "break" or "goto" when whatever condition it is
 * testing for succeeds (or there is an unrecoverable error).
 */
bool
virTimeBackOffWait(virTimeBackOffVar *var)
{
    unsigned long long next, t = 0;

    ignore_value(virTimeMillisNowRaw(&t));

    VIR_DEBUG("t=%llu, limit=%llu", t, var->limit_t);

    if (t > var->limit_t)
        return false;               /* ends the while loop */

    /* Compute next wait time. Cap at VIR_TIME_BACKOFF_CAP
     * to avoid long useless sleeps. */
    next = var->next;
    if (var->next < VIR_TIME_BACKOFF_CAP)
        var->next *= 2;
    else if (var->next > VIR_TIME_BACKOFF_CAP)
        var->next = VIR_TIME_BACKOFF_CAP;

    /* If sleeping would take us beyond the limit, then shorten the
     * sleep.  This is so we always run the body just before the final
     * timeout.
     */
    if (t + next > var->limit_t)
        next = var->limit_t - t;

    VIR_DEBUG("sleeping for %llu ms", next);

    g_usleep(next * 1000);
    return true;
}
