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

/* Don't call these directly - use the macros below */
int virStrdup(char **dest, const char *src, bool report, int domcode,
              const char *filename, const char *funcname, size_t linenr)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1);

int virStrndup(char **dest, const char *src, ssize_t n, bool report, int domcode,
               const char *filename, const char *funcname, size_t linenr)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1);

/**
 * VIR_STRDUP:
 * @dst: variable to hold result (char*, not char**)
 * @src: string to duplicate
 *
 * Duplicate @src string and store it into @dst.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns -1 on failure (with OOM error reported), 0 if @src was NULL,
 * 1 if @src was copied
 */
# define VIR_STRDUP(dst, src) virStrdup(&(dst), src, true, VIR_FROM_THIS, \
                                        __FILE__, __FUNCTION__, __LINE__)

/**
 * VIR_STRDUP_QUIET:
 * @dst: variable to hold result (char*, not char**)
 * @src: string to duplicate
 *
 * Duplicate @src string and store it into @dst.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns -1 on failure, 0 if @src was NULL, 1 if @src was copied
 */
# define VIR_STRDUP_QUIET(dst, src) virStrdup(&(dst), src, false, 0, NULL, NULL, 0)

/**
 * VIR_STRNDUP:
 * @dst: variable to hold result (char*, not char**)
 * @src: string to duplicate
 * @n: the maximum number of bytes to copy
 *
 * Duplicate @src string and store it into @dst. If @src is longer than @n,
 * only @n bytes are copied and terminating null byte '\0' is added. If @n
 * is a negative number, then the whole @src string is copied. That is,
 * VIR_STRDUP(dst, src) and VIR_STRNDUP(dst, src, -1) are equal.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns -1 on failure (with OOM error reported), 0 if @src was NULL,
 * 1 if @src was copied
 */
# define VIR_STRNDUP(dst, src, n) virStrndup(&(dst), src, n, true,    \
                                             VIR_FROM_THIS, __FILE__, \
                                             __FUNCTION__, __LINE__)

/**
 * VIR_STRNDUP_QUIET:
 * @dst: variable to hold result (char*, not char**)
 * @src: string to duplicate
 * @n: the maximum number of bytes to copy
 *
 * Duplicate @src string and store it into @dst. If @src is longer than @n,
 * only @n bytes are copied and terminating null byte '\0' is added. If @n
 * is a negative number, then the whole @src string is copied. That is,
 * VIR_STRDUP_QUIET(dst, src) and VIR_STRNDUP_QUIET(dst, src, -1) are
 * equal.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns -1 on failure, 0 if @src was NULL, 1 if @src was copied
 */
# define VIR_STRNDUP_QUIET(dst, src, n) virStrndup(&(dst), src, n, false, \
                                                   0, NULL, NULL, 0)

size_t virStringListLength(char **strings);

#endif /* __VIR_STRING_H__ */
