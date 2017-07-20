/*
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

char **virStringSplitCount(const char *string,
                           const char *delim,
                           size_t max_tokens,
                           size_t *tokcount)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char **virStringSplit(const char *string,
                      const char *delim,
                      size_t max_tokens)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *virStringListJoin(const char **strings,
                        const char *delim)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char **virStringListAdd(const char **strings,
                        const char *item);
void virStringListRemove(char ***strings,
                         const char *item);

void virStringListFree(char **strings);
void virStringListFreeCount(char **strings,
                            size_t count);

bool virStringListHasString(const char **strings,
                            const char *needle);
char *virStringListGetFirstWithPrefix(char **strings,
                                      const char *prefix)
    ATTRIBUTE_NONNULL(2);

char *virArgvToString(const char *const *argv);

int virStrToLong_i(char const *s,
                   char **end_ptr,
                   int base,
                   int *result)
    ATTRIBUTE_RETURN_CHECK;

int virStrToLong_ui(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned int *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_uip(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned int *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_l(char const *s,
                   char **end_ptr,
                   int base,
                   long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_ul(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_ulp(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_ull(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToLong_ullp(char const *s,
                      char **end_ptr,
                      int base,
                      unsigned long long *result)
    ATTRIBUTE_RETURN_CHECK;
int virStrToDouble(char const *s,
                   char **end_ptr,
                   double *result)
    ATTRIBUTE_RETURN_CHECK;

int virDoubleToStr(char **strp, double number)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

void virSkipSpaces(const char **str) ATTRIBUTE_NONNULL(1);
void virSkipSpacesAndBackslash(const char **str) ATTRIBUTE_NONNULL(1);
void virTrimSpaces(char *str, char **endp) ATTRIBUTE_NONNULL(1);
void virSkipSpacesBackwards(const char *str, char **endp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virStringIsEmpty(const char *str);

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
int virAsprintfInternal(bool report, int domcode, const char *filename,
                        const char *funcname, size_t linenr, char **strp,
                        const char *fmt, ...)
    ATTRIBUTE_NONNULL(6) ATTRIBUTE_NONNULL(7) ATTRIBUTE_FMT_PRINTF(7, 8)
    ATTRIBUTE_RETURN_CHECK;
int virVasprintfInternal(bool report, int domcode, const char *filename,
                         const char *funcname, size_t linenr, char **strp,
                         const char *fmt, va_list list)
    ATTRIBUTE_NONNULL(6) ATTRIBUTE_NONNULL(7) ATTRIBUTE_FMT_PRINTF(7, 0)
    ATTRIBUTE_RETURN_CHECK;

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

size_t virStringListLength(const char * const *strings);

/**
 * virVasprintf
 *
 * Like glibc's vasprintf but makes sure *strp == NULL on failure, in which
 * case the OOM error is reported too.
 *
 * Returns -1 on failure (with OOM error reported), number of bytes printed
 * on success.
 */
# define virVasprintf(strp, fmt, list) \
    virVasprintfInternal(true, VIR_FROM_THIS, __FILE__, __FUNCTION__, \
                         __LINE__, strp, fmt, list)

/**
 * virVasprintfQuiet
 *
 * Like glibc's vasprintf but makes sure *strp == NULL on failure.
 *
 * Returns -1 on failure, number of bytes printed on success.
 */
# define virVasprintfQuiet(strp, fmt, list) \
    virVasprintfInternal(false, 0, NULL, NULL, 0, strp, fmt, list)

/**
 * virAsprintf:
 * @strp: variable to hold result (char **)
 * @fmt: printf format
 *
 * Like glibc's_asprintf but makes sure *strp == NULL on failure, in which case
 * the OOM error is reported too.
 *
 * Returns -1 on failure (with OOM error reported), number of bytes printed
 * on success.
 */

# define virAsprintf(strp, ...) \
    virAsprintfInternal(true, VIR_FROM_THIS, __FILE__, __FUNCTION__, __LINE__, \
                        strp, __VA_ARGS__)

/**
 * virAsprintfQuiet:
 * @strp: variable to hold result (char **)
 * @fmt: printf format
 *
 * Like glibc's_asprintf but makes sure *strp == NULL on failure.
 *
 * Returns -1 on failure, number of bytes printed on success.
 */

# define virAsprintfQuiet(strp, ...) \
    virAsprintfInternal(false, 0, NULL, NULL, 0, \
                        strp, __VA_ARGS__)

int virStringSortCompare(const void *a, const void *b);
int virStringSortRevCompare(const void *a, const void *b);
int virStringToUpper(char **dst, const char *src);

ssize_t virStringSearch(const char *str,
                        const char *regexp,
                        size_t max_results,
                        char ***matches)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

bool virStringMatch(const char *str,
                    const char *regexp);

char *virStringReplace(const char *haystack,
                       const char *oldneedle,
                       const char *newneedle)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virStringStripIPv6Brackets(char *str);
bool virStringHasControlChars(const char *str);
void virStringStripControlChars(char *str);

bool virStringIsPrintable(const char *str);
bool virStringBufferIsPrintable(const uint8_t *buf, size_t buflen);

char *virStringEncodeBase64(const uint8_t *buf, size_t buflen);

void virStringTrimOptionalNewline(char *str);

int virStringParsePort(const char *str,
                       unsigned int *port)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

#endif /* __VIR_STRING_H__ */
