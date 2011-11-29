/*
 * virtime.h: Time handling functions
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_TIME_H__
# define __VIR_TIME_H__

# include <time.h>

# include "internal.h"

/* The format string we intend to use is:
 *
 * Yr  Mon  Day  Hour  Min  Sec Ms   TZ
 * %4d-%02d-%02d %02d:%02d:%02d.%03d+0000
 *
 */
# define VIR_TIME_STRING_BUFLEN \
    (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 5 + 1)
/*   Yr      Mon     Day     Hour    Min     Sec     Ms  TZ  NULL */

/* These APIs are async signal safe and return -1, setting
 * errno on failure */
int virTimeMillisNowRaw(unsigned long long *now)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virTimeFieldsNowRaw(struct tm *fields)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virTimeFieldsThenRaw(unsigned long long when, struct tm *fields)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virTimeStringNowRaw(char *buf)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virTimeStringThenRaw(unsigned long long when, char *buf)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;


/* These APIs are *not* async signal safe and return -1,
 * raising a libvirt error on failure
 */
int virTimeMillisNow(unsigned long long *now)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virTimeFieldsNow(struct tm *fields)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virTimeFieldsThen(unsigned long long when, struct tm *fields)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
char *virTimeStringNow(void);
char *virTimeStringThen(unsigned long long when);


#endif
