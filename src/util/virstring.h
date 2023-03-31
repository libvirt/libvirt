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
 */

#pragma once

#include "internal.h"

#define VIR_INT64_STR_BUFLEN 21

int virStrToLong_i(char const *s,
                   char **end_ptr,
                   int base,
                   int *result)
    G_GNUC_WARN_UNUSED_RESULT;

int virStrToLong_ui(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned int *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_uip(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned int *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_ul(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned long *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_ulp(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_ull(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long long *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToLong_ullp(char const *s,
                      char **end_ptr,
                      int base,
                      unsigned long long *result)
    G_GNUC_WARN_UNUSED_RESULT;
int virStrToDouble(char const *s,
                   char **end_ptr,
                   double *result)
    G_GNUC_WARN_UNUSED_RESULT;

int virDoubleToStr(char **strp, double number)
    ATTRIBUTE_NONNULL(1);

void virSkipSpaces(const char **str) ATTRIBUTE_NONNULL(1);
void virSkipSpacesAndBackslash(const char **str) ATTRIBUTE_NONNULL(1);
void virSkipToDigit(const char **str) ATTRIBUTE_NONNULL(1);
void virTrimSpaces(char *str, char **endp) ATTRIBUTE_NONNULL(1);
void virSkipSpacesBackwards(const char *str, char **endp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virStringIsEmpty(const char *str);

int virStrcpy(char *dest, const char *src, size_t destbytes);
#define virStrcpyStatic(dest, src) virStrcpy((dest), (src), sizeof(dest))

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

bool virStringHasSuffix(const char *str,
                        const char *suffix);
bool virStringHasCaseSuffix(const char *str,
                            const char *suffix);
bool virStringStripSuffix(char *str,
                          const char *suffix) G_GNUC_WARN_UNUSED_RESULT;
bool virStringMatchesNameSuffix(const char *file,
                                const char *name,
                                const char *suffix);

void virStringStripIPv6Brackets(char *str);
bool virStringHasChars(const char *str,
                       const char *chars);
bool virStringHasControlChars(const char *str);
void virStringStripControlChars(char *str);
void virStringFilterChars(char *str, const char *valid);

bool virStringIsPrintable(const char *str);
bool virStringBufferIsPrintable(const uint8_t *buf, size_t buflen);

void virStringTrimOptionalNewline(char *str);

int virStringParsePort(const char *str,
                       unsigned int *port)
    ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virStringParseYesNo(const char *str,
                        bool *result)
    G_GNUC_WARN_UNUSED_RESULT;

int virStringParseVersion(unsigned long long *version,
                          const char *str,
                          bool allowMissing);
