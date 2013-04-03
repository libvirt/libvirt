/*
 * Copyright (C) 2007-2012 Red Hat, Inc.
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
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_STRING_H__
# define __VIR_STRING_H__

# include <stdarg.h>

# include "internal.h"

char **virStringSplit(const char *string,
                      const char *delim,
                      size_t max_tokens)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *virStringJoin(const char **strings,
                    const char *delim)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virStringFreeList(char **strings);

bool virStringArrayHasString(char **strings, const char *needle);

char *virArgvToString(const char *const *argv);

int virStrToLong_i(char const *s,
                   char **end_ptr,
                   int base,
                   int *result);

int virStrToLong_ui(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned int *result);
int virStrToLong_l(char const *s,
                   char **end_ptr,
                   int base,
                   long *result);
int virStrToLong_ul(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned long *result);
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result);
int virStrToLong_ull(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long long *result);
int virStrToDouble(char const *s,
                   char **end_ptr,
                   double *result);

void virSkipSpaces(const char **str) ATTRIBUTE_NONNULL(1);
void virSkipSpacesAndBackslash(const char **str) ATTRIBUTE_NONNULL(1);
void virTrimSpaces(char *str, char **endp) ATTRIBUTE_NONNULL(1);
void virSkipSpacesBackwards(const char *str, char **endp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virAsprintf(char **strp, const char *fmt, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3)
    ATTRIBUTE_RETURN_CHECK;
int virVasprintf(char **strp, const char *fmt, va_list list)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 0)
    ATTRIBUTE_RETURN_CHECK;
char *virStrncpy(char *dest, const char *src, size_t n, size_t destbytes)
    ATTRIBUTE_RETURN_CHECK;
char *virStrcpy(char *dest, const char *src, size_t destbytes)
    ATTRIBUTE_RETURN_CHECK;
# define virStrcpyStatic(dest, src) virStrcpy((dest), (src), sizeof(dest))
#endif /* __VIR_STRING_H__ */
