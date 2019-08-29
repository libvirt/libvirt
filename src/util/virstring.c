/*
 * Copyright (C) 2012-2015 Red Hat, Inc.
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

#include <config.h>

#include <regex.h>
#include <locale.h>

#include "base64.h"
#include "c-ctype.h"
#include "virstring.h"
#include "virthread.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.string");

/*
 * The following virStringSplit & virStringListJoin methods
 * are derived from g_strsplit / g_strjoin in glib2,
 * also available under the LGPLv2+ license terms
 */

/**
 * virStringSplitCount:
 * @string: a string to split
 * @delim: a string which specifies the places at which to split
 *     the string. The delimiter is not included in any of the resulting
 *     strings, unless @max_tokens is reached.
 * @max_tokens: the maximum number of pieces to split @string into.
 *     If this is 0, the string is split completely.
 * @tokcount: If provided, the value is set to the count of pieces the string
 *            was split to excluding the terminating NULL element.
 *
 * Splits a string into a maximum of @max_tokens pieces, using the given
 * @delim. If @max_tokens is reached, the remainder of @string is
 * appended to the last token.
 *
 * As a special case, the result of splitting the empty string "" is an empty
 * vector, not a vector containing a single string. The reason for this
 * special case is that being able to represent an empty vector is typically
 * more useful than consistent handling of empty elements. If you do need
 * to represent empty elements, you'll need to check for the empty string
 * before calling virStringSplit().
 *
 * Return value: a newly-allocated NULL-terminated array of strings. Use
 *    virStringListFree() to free it.
 */
char **
virStringSplitCount(const char *string,
                    const char *delim,
                    size_t max_tokens,
                    size_t *tokcount)
{
    char **tokens = NULL;
    size_t ntokens = 0;
    size_t maxtokens = 0;
    const char *remainder = string;
    char *tmp;
    size_t i;

    if (max_tokens == 0)
        max_tokens = INT_MAX;

    tmp = strstr(remainder, delim);
    if (tmp) {
        size_t delimlen = strlen(delim);

        while (--max_tokens && tmp) {
            size_t len = tmp - remainder;

            if (VIR_RESIZE_N(tokens, maxtokens, ntokens, 1) < 0)
                goto error;

            if (VIR_STRNDUP(tokens[ntokens], remainder, len) < 0)
                goto error;
            ntokens++;
            remainder = tmp + delimlen;
            tmp = strstr(remainder, delim);
        }
    }
    if (*string) {
        if (VIR_RESIZE_N(tokens, maxtokens, ntokens, 1) < 0)
            goto error;

        if (VIR_STRDUP(tokens[ntokens], remainder) < 0)
            goto error;
        ntokens++;
    }

    if (VIR_RESIZE_N(tokens, maxtokens, ntokens, 1) < 0)
        goto error;
    tokens[ntokens++] = NULL;

    if (tokcount)
        *tokcount = ntokens - 1;

    return tokens;

 error:
    for (i = 0; i < ntokens; i++)
        VIR_FREE(tokens[i]);
    VIR_FREE(tokens);
    return NULL;
}


char **
virStringSplit(const char *string,
               const char *delim,
               size_t max_tokens)
{
    return virStringSplitCount(string, delim, max_tokens, NULL);
}


/**
 * virStringListJoin:
 * @strings: a NULL-terminated array of strings to join
 * @delim: a string to insert between each of the strings
 *
 * Joins a number of strings together to form one long string, with the
 * @delim inserted between each of them. The returned string
 * should be freed with VIR_FREE().
 *
 * Returns: a newly-allocated string containing all of the strings joined
 *     together, with @delim between them
 */
char *virStringListJoin(const char **strings,
                        const char *delim)
{
    char *ret;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    while (*strings) {
        virBufferAdd(&buf, *strings, -1);
        if (*(strings+1))
            virBufferAdd(&buf, delim, -1);
        strings++;
    }
    if (virBufferCheckError(&buf) < 0)
        return NULL;
    ret = virBufferContentAndReset(&buf);
    if (!ret)
        ignore_value(VIR_STRDUP(ret, ""));
    return ret;
}


/**
 * virStringListAdd:
 * @strings: a NULL-terminated array of strings
 * @item: string to add
 *
 * Appends @item into string list @strings. If *@strings is not
 * allocated yet new string list is created.
 *
 * Returns: 0 on success,
 *         -1 otherwise
 */
int
virStringListAdd(char ***strings,
                 const char *item)
{
    size_t i = virStringListLength((const char **) *strings);

    if (VIR_EXPAND_N(*strings, i, 2) < 0 ||
        VIR_STRDUP((*strings)[i - 2], item) < 0)
        return -1;

    return 0;
}


/**
 * virStringListRemove:
 * @strings: a NULL-terminated array of strings
 * @item: string to remove
 *
 * Remove every occurrence of @item in list of @strings.
 */
void
virStringListRemove(char ***strings,
                    const char *item)
{
    size_t r, w = 0;

    if (!strings || !*strings)
        return;

    for (r = 0; (*strings)[r]; r++) {
        if (STREQ((*strings)[r], item)) {
            VIR_FREE((*strings)[r]);
            continue;
        }
        if (r != w)
            (*strings)[w] = (*strings)[r];
        w++;
    }

    if (w == 0) {
        VIR_FREE(*strings);
    } else {
        (*strings)[w] = NULL;
        ignore_value(VIR_REALLOC_N(*strings, w + 1));
    }
}


/**
 * virStringListMerge:
 * @dst: a NULL-terminated array of strings to expand
 * @src: a NULL-terminated array of strings
 *
 * Merges @src into @dst. Upon successful return from this
 * function, @dst is resized to $(dst + src) elements and @src is
 * freed.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virStringListMerge(char ***dst,
                   char ***src)
{
    size_t dst_len, src_len, i;

    if (!src || !*src)
        return 0;

    dst_len = virStringListLength((const char **) *dst);
    src_len = virStringListLength((const char **) *src);

    if (VIR_REALLOC_N(*dst, dst_len + src_len + 1) < 0)
        return -1;

    for (i = 0; i <= src_len; i++)
        (*dst)[i + dst_len] = (*src)[i];

    /* Don't call virStringListFree() as it would free strings in
     * @src. */
    VIR_FREE(*src);
    return 0;
}


/**
 * virStringListCopy:
 * @dst: where to store the copy of @strings
 * @src: a NULL-terminated array of strings
 *
 * Makes a deep copy of the @src string list and stores it in @dst. Callers
 * are responsible for freeing @dst.
 *
 * Returns 0 on success, -1 on error.
 */
int
virStringListCopy(char ***dst,
                  const char **src)
{
    char **copy = NULL;
    size_t i;

    *dst = NULL;

    if (!src)
        return 0;

    if (VIR_ALLOC_N(copy, virStringListLength(src) + 1) < 0)
        goto error;

    for (i = 0; src[i]; i++) {
        if (VIR_STRDUP(copy[i], src[i]) < 0)
            goto error;
    }

    *dst = copy;
    return 0;

 error:
    virStringListFree(copy);
    return -1;
}


/**
 * virStringListFree:
 * @strings: a NULL-terminated array of strings to free
 *
 * Frees a NULL-terminated array of strings, and the array itself.
 * If called on a NULL value, virStringListFree() simply returns.
 */
void virStringListFree(char **strings)
{
    char **tmp = strings;
    while (tmp && *tmp) {
        VIR_FREE(*tmp);
        tmp++;
    }
    VIR_FREE(strings);
}


void virStringListAutoFree(char ***strings)
{
    if (!*strings)
        return;

    virStringListFree(*strings);
    *strings = NULL;
}


/**
 * virStringListFreeCount:
 * @strings: array of strings to free
 * @count: number of elements in the array
 *
 * Frees a string array of @count length.
 */
void
virStringListFreeCount(char **strings,
                       size_t count)
{
    size_t i;

    if (!strings)
        return;

    for (i = 0; i < count; i++)
        VIR_FREE(strings[i]);

    VIR_FREE(strings);
}


bool
virStringListHasString(const char **strings,
                       const char *needle)
{
    size_t i = 0;

    if (!strings)
        return false;

    while (strings[i]) {
        if (STREQ(strings[i++], needle))
            return true;
    }

    return false;
}

char *
virStringListGetFirstWithPrefix(char **strings,
                                const char *prefix)
{
    size_t i = 0;

    if (!strings)
        return NULL;

    while (strings[i]) {
        if (STRPREFIX(strings[i], prefix))
            return strings[i] + strlen(prefix);
        i++;
    }

    return NULL;
}

/* Like strtol, but produce an "int" result, and check more carefully.
   Return 0 upon success;  return -1 to indicate failure.
   When END_PTR is NULL, the byte after the final valid digit must be NUL.
   Otherwise, it's like strtol and lets the caller check any suffix for
   validity.  This function is careful to return -1 when the string S
   represents a number that is not representable as an "int". */
int
virStrToLong_i(char const *s, char **end_ptr, int base, int *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base); /* exempt from syntax-check */
    err = (errno || (!end_ptr && *p) || p == s || (int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned int"
 * value.  This version allows twos-complement wraparound of negative
 * numbers. */
int
virStrToLong_ui(char const *s, char **end_ptr, int base, unsigned int *result)
{
    unsigned long int val;
    char *p;
    bool err = false;

    errno = 0;
    val = strtoul(s, &p, base); /* exempt from syntax-check */

    /* This one's tricky.  We _want_ to allow "-1" as shorthand for
     * UINT_MAX regardless of whether long is 32-bit or 64-bit.  But
     * strtoul treats "-1" as ULONG_MAX, and going from ulong back
     * to uint differs depending on the size of long. */
    if (sizeof(long) > sizeof(int) && memchr(s, '-', p - s)) {
        if (-val > UINT_MAX)
            err = true;
        else
            val &= 0xffffffff;
    }

    err |= (errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned int"
 * value.  This version rejects any negative signs.  */
int
virStrToLong_uip(char const *s, char **end_ptr, int base, unsigned int *result)
{
    unsigned long int val;
    char *p;
    bool err = false;

    errno = 0;
    val = strtoul(s, &p, base); /* exempt from syntax-check */
    err = (memchr(s, '-', p - s) ||
           errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce a "long" value.  */
int
virStrToLong_l(char const *s, char **end_ptr, int base, long *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base); /* exempt from syntax-check */
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long"
 * value.  This version allows twos-complement wraparound of negative
 * numbers. */
int
virStrToLong_ul(char const *s, char **end_ptr, int base, unsigned long *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base); /* exempt from syntax-check */
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long"
 * value.  This version rejects any negative signs.  */
int
virStrToLong_ulp(char const *s, char **end_ptr, int base,
                 unsigned long *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base); /* exempt from syntax-check */
    err = (memchr(s, '-', p - s) ||
           errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce a "long long" value.  */
int
virStrToLong_ll(char const *s, char **end_ptr, int base, long long *result)
{
    long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoll(s, &p, base); /* exempt from syntax-check */
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long
 * long" value.  This version allows twos-complement wraparound of
 * negative numbers. */
int
virStrToLong_ull(char const *s, char **end_ptr, int base,
                 unsigned long long *result)
{
    unsigned long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoull(s, &p, base); /* exempt from syntax-check */
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long
 * long" value.  This version rejects any negative signs.  */
int
virStrToLong_ullp(char const *s, char **end_ptr, int base,
                  unsigned long long *result)
{
    unsigned long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoull(s, &p, base); /* exempt from syntax-check */
    err = (memchr(s, '-', p - s) ||
           errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* In case thread-safe locales are available */
#if HAVE_NEWLOCALE

typedef locale_t virLocale;
static virLocale virLocaleRaw;

static int
virLocaleOnceInit(void)
{
    virLocaleRaw = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (!virLocaleRaw)
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLocale);

/**
 * virLocaleSetRaw:
 *
 * @oldlocale: set to old locale pointer
 *
 * Sets the locale to 'C' to allow operating on non-localized objects.
 * Returns 0 on success -1 on error.
 */
static int
virLocaleSetRaw(virLocale *oldlocale)
{
    if (virLocaleInitialize() < 0)
        return -1;
    *oldlocale = uselocale(virLocaleRaw);
    return 0;
}

static void
virLocaleRevert(virLocale *oldlocale)
{
    uselocale(*oldlocale);
}

static void
virLocaleFixupRadix(char **strp ATTRIBUTE_UNUSED)
{
}

#else /* !HAVE_NEWLOCALE */

typedef int virLocale;

static int
virLocaleSetRaw(virLocale *oldlocale ATTRIBUTE_UNUSED)
{
    return 0;
}

static void
virLocaleRevert(virLocale *oldlocale ATTRIBUTE_UNUSED)
{
}

static void
virLocaleFixupRadix(char **strp)
{
    char *radix, *tmp;
    struct lconv *lc;

    lc = localeconv();
    radix = lc->decimal_point;
    tmp = strstr(*strp, radix);
    if (tmp) {
        *tmp = '.';
        if (strlen(radix) > 1)
            memmove(tmp + 1, tmp + strlen(radix), strlen(*strp) - (tmp - *strp));
    }
}

#endif /* !HAVE_NEWLOCALE */


/**
 * virStrToDouble
 *
 * converts string with C locale (thread-safe) to double.
 *
 * Returns -1 on error or returns 0 on success.
 */
int
virStrToDouble(char const *s,
               char **end_ptr,
               double *result)
{
    virLocale oldlocale;
    double val;
    char *p;
    int err;

    errno = 0;
    if (virLocaleSetRaw(&oldlocale) < 0)
        return -1;
    val = strtod(s, &p); /* exempt from syntax-check */
    virLocaleRevert(&oldlocale);

    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/**
 * virDoubleToStr
 *
 * converts double to string with C locale (thread-safe).
 *
 * Returns -1 on error, size of the string otherwise.
 */
int
virDoubleToStr(char **strp, double number)
{
    virLocale oldlocale;
    int ret = -1;

    if (virLocaleSetRaw(&oldlocale) < 0)
        return -1;

    ret = virAsprintf(strp, "%lf", number);

    virLocaleRevert(&oldlocale);
    virLocaleFixupRadix(strp);

    return ret;
}


int
virVasprintfInternal(char **strp,
                     const char *fmt,
                     va_list list)
{
    int ret;

    if ((ret = vasprintf(strp, fmt, list)) == -1)
        abort();

    return ret;
}

int
virAsprintfInternal(char **strp,
                    const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = virVasprintfInternal(strp, fmt, ap);
    va_end(ap);
    return ret;
}

/**
 * virStrncpy:
 *
 * @dest: destination buffer
 * @src: source buffer
 * @n: number of bytes to copy
 * @destbytes: number of bytes the destination can accommodate
 *
 * Copies the first @n bytes of @src to @dest.
 *
 * @src must be NULL-terminated; if successful, @dest is guaranteed to
 * be NULL-terminated as well.
 *
 * @n must be a reasonable value, that is, it must not exceed either
 * the length of @src or the size of @dest. For the latter constraint,
 * the fact that @dest needs to accommodate a NULL byte in addition to
 * the bytes copied from @src must be taken into account.
 *
 * If you want to copy *all* of @src to @dest, use virStrcpy() or
 * virStrcpyStatic() instead.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virStrncpy(char *dest, const char *src, size_t n, size_t destbytes)
{
    size_t src_len = strlen(src);

    /* As a special case, -1 means "copy the entire string".
     *
     * This is to avoid calling strlen() twice, once in the virStrcpy()
     * wrapper and once here for bound checking purposes. */
    if (n == -1)
        n = src_len;

    if (n <= 0 || n > src_len || n > (destbytes - 1))
        return -1;

    memcpy(dest, src, n);
    dest[n] = '\0';

    return 0;
}

/**
 * virStrcpy:
 *
 * @dest: destination buffer
 * @src: source buffer
 * @destbytes: number of bytes the destination can accommodate
 *
 * Copies @src to @dest.
 *
 * See virStrncpy() for more information.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virStrcpy(char *dest, const char *src, size_t destbytes)
{
    return virStrncpy(dest, src, -1, destbytes);
}

/**
 * virSkipSpaces:
 * @str: pointer to the char pointer used
 *
 * Skip potential blanks, this includes space tabs, line feed,
 * carriage returns.
 */
void
virSkipSpaces(const char **str)
{
    const char *cur = *str;

    while (c_isspace(*cur))
        cur++;
    *str = cur;
}

/**
 * virSkipSpacesAndBackslash:
 * @str: pointer to the char pointer used
 *
 * Like virSkipSpaces, but also skip backslashes erroneously emitted
 * by xend
 */
void
virSkipSpacesAndBackslash(const char **str)
{
    const char *cur = *str;

    while (c_isspace(*cur) || *cur == '\\')
        cur++;
    *str = cur;
}

/**
 * virTrimSpaces:
 * @str: string to modify to remove all trailing spaces
 * @endp: track the end of the string
 *
 * If @endp is NULL on entry, then all spaces prior to the trailing
 * NUL in @str are removed, by writing NUL into the appropriate
 * location.  If @endp is non-NULL but points to a NULL pointer,
 * then all spaces prior to the trailing NUL in @str are removed,
 * NUL is written to the new string end, and endp is set to the
 * location of the (new) string end.  If @endp is non-NULL and
 * points to a non-NULL pointer, then that pointer is used as
 * the end of the string, endp is set to the (new) location, but
 * no NUL pointer is written into the string.
 */
void
virTrimSpaces(char *str, char **endp)
{
    char *end;

    if (!endp || !*endp)
        end = str + strlen(str);
    else
        end = *endp;
    while (end > str && c_isspace(end[-1]))
        end--;
    if (endp) {
        if (!*endp)
            *end = '\0';
        *endp = end;
    } else {
        *end = '\0';
    }
}

/**
 * virSkipSpacesBackwards:
 * @str: start of string
 * @endp: on entry, *endp must be NULL or a location within @str, on exit,
 * will be adjusted to skip trailing spaces, or to NULL if @str had nothing
 * but spaces.
 */
void
virSkipSpacesBackwards(const char *str, char **endp)
{
    /* Casting away const is safe, since virTrimSpaces does not
     * modify string with this particular usage.  */
    char *s = (char*) str;

    if (!*endp)
        *endp = s + strlen(s);
    virTrimSpaces(s, endp);
    if (s == *endp)
        *endp = NULL;
}

/**
 * virStringIsEmpty:
 * @str: string to check
 *
 * Returns true if string is empty (may contain only whitespace) or NULL.
 */
bool
virStringIsEmpty(const char *str)
{
    if (!str)
        return true;

    virSkipSpaces(&str);
    return str[0] == '\0';
}

/**
 * virStrdup:
 * @dest: where to store duplicated string
 * @src: the source string to duplicate
 *
 * Wrapper over strdup, which aborts on OOM error.
 *
 * Returns: 0 for NULL src, 1 on successful copy, aborts on OOM
 */
int
virStrdup(char **dest,
          const char *src)
{
    *dest = NULL;
    if (!src)
        return 0;
    if (!(*dest = strdup(src)))
        abort();

    return 1;
}

/**
 * virStrndup:
 * @dest: where to store duplicated string
 * @src: the source string to duplicate
 * @n: how many bytes to copy
 *
 * Wrapper over strndup, which aborts on OOM error.
 *
 * In case @n is smaller than zero, the whole @src string is
 * copied.
 *
 * Returns: 0 for NULL src, 1 on successful copy, aborts on OOM
 */
int
virStrndup(char **dest,
           const char *src,
           ssize_t n)
{
    *dest = NULL;
    if (!src)
        return 0;
    if (n < 0)
        n = strlen(src);
    if (!(*dest = strndup(src, n)))
        abort();

    return 1;
}


size_t virStringListLength(const char * const *strings)
{
    size_t i = 0;

    while (strings && strings[i])
        i++;

    return i;
}


/**
 * virStringSortCompare:
 *
 * A comparator function for sorting strings in
 * normal order with qsort().
 */
int virStringSortCompare(const void *a, const void *b)
{
    const char **sa = (const char**)a;
    const char **sb = (const char**)b;

    return strcmp(*sa, *sb);
}

/**
 * virStringSortRevCompare:
 *
 * A comparator function for sorting strings in
 * reverse order with qsort().
 */
int virStringSortRevCompare(const void *a, const void *b)
{
    const char **sa = (const char**)a;
    const char **sb = (const char**)b;

    return strcmp(*sb, *sa);
}

/**
 * virStringSearch:
 * @str: string to search
 * @regexp: POSIX Extended regular expression pattern used for matching
 * @max_matches: maximum number of substrings to return
 * @matches: pointer to an array to be filled with NULL terminated list of matches
 *
 * Performs a POSIX extended regex search against a string and return all matching substrings.
 * The @matches value should be freed with virStringListFree() when no longer
 * required.
 *
 * @code
 *  char *source = "6853a496-1c10-472e-867a-8244937bd6f0
 *                  773ab075-4cd7-4fc2-8b6e-21c84e9cb391
 *                  bbb3c75c-d60f-43b0-b802-fd56b84a4222
 *                  60c04aa1-0375-4654-8d9f-e149d9885273
 *                  4548d465-9891-4c34-a184-3b1c34a26aa8";
 *  char **matches = NULL;
 *  virStringSearch(source,
 *                  "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
 *                  3,
 *                  &matches);
 *
 *  // matches[0] == "6853a496-1c10-472e-867a-8244937bd6f0";
 *  // matches[1] == "773ab075-4cd7-4fc2-8b6e-21c84e9cb391";
 *  // matches[2] == "bbb3c75c-d60f-43b0-b802-fd56b84a4222"
 *  // matches[3] == NULL;
 *
 *  virStringListFree(matches);
 * @endcode
 *
 * Returns: -1 on error, or number of matches
 */
ssize_t
virStringSearch(const char *str,
                const char *regexp,
                size_t max_matches,
                char ***matches)
{
    regex_t re;
    regmatch_t rem;
    size_t nmatches = 0;
    ssize_t ret = -1;
    int rv = -1;

    *matches = NULL;

    VIR_DEBUG("search '%s' for '%s'", str, regexp);

    if ((rv = regcomp(&re, regexp, REG_EXTENDED)) != 0) {
        char error[100];
        regerror(rv, &re, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error while compiling regular expression '%s': %s"),
                       regexp, error);
        return -1;
    }

    if (re.re_nsub != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Regular expression '%s' must have exactly 1 match group, not %zu"),
                       regexp, re.re_nsub);
        goto cleanup;
    }

    /* '*matches' must always be NULL terminated in every iteration
     * of the loop, so start by allocating 1 element
     */
    if (VIR_EXPAND_N(*matches, nmatches, 1) < 0)
        goto cleanup;

    while ((nmatches - 1) < max_matches) {
        char *match;

        if (regexec(&re, str, 1, &rem, 0) != 0)
            break;

        if (VIR_EXPAND_N(*matches, nmatches, 1) < 0)
            goto cleanup;

        if (VIR_STRNDUP(match, str + rem.rm_so,
                        rem.rm_eo - rem.rm_so) < 0)
            goto cleanup;

        VIR_DEBUG("Got '%s'", match);

        (*matches)[nmatches-2] = match;

        str = str + rem.rm_eo;
    }

    ret = nmatches - 1; /* don't count the trailing null */

 cleanup:
    regfree(&re);
    if (ret < 0) {
        virStringListFree(*matches);
        *matches = NULL;
    }
    return ret;
}

/**
 * virStringMatch:
 * @str: string to match
 * @regexp: POSIX Extended regular expression pattern used for matching
 *
 * Performs a POSIX extended regex match against a string.
 * Returns true on match, false on error or no match.
 */
bool
virStringMatch(const char *str,
               const char *regexp)
{
    regex_t re;
    int rv;

    VIR_DEBUG("match '%s' for '%s'", str, regexp);

    if ((rv = regcomp(&re, regexp, REG_EXTENDED | REG_NOSUB)) != 0) {
        char error[100];
        regerror(rv, &re, error, sizeof(error));
        VIR_WARN("error while compiling regular expression '%s': %s",
                 regexp, error);
        return false;
    }

    rv = regexec(&re, str, 0, NULL, 0);

    regfree(&re);

    return rv == 0;
}

/**
 * virStringReplace:
 * @haystack: the source string to process
 * @oldneedle: the substring to locate
 * @newneedle: the substring to insert
 *
 * Search @haystack and replace all occurrences of @oldneedle with @newneedle.
 *
 * Returns: a new string with all the replacements, or NULL on error
 */
char *
virStringReplace(const char *haystack,
                 const char *oldneedle,
                 const char *newneedle)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *tmp1, *tmp2;
    size_t oldneedlelen = strlen(oldneedle);
    size_t newneedlelen = strlen(newneedle);

    tmp1 = haystack;
    tmp2 = NULL;

    while (tmp1) {
        tmp2 = strstr(tmp1, oldneedle);

        if (tmp2) {
            virBufferAdd(&buf, tmp1, (tmp2 - tmp1));
            virBufferAdd(&buf, newneedle, newneedlelen);
            tmp2 += oldneedlelen;
        } else {
            virBufferAdd(&buf, tmp1, -1);
        }

        tmp1 = tmp2;
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

bool
virStringHasSuffix(const char *str,
                   const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return false;

    return STREQ(str + len - suffixlen, suffix);
}

bool
virStringHasCaseSuffix(const char *str,
                       const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return false;

    return STRCASEEQ(str + len - suffixlen, suffix);
}

bool
virStringStripSuffix(char *str,
                     const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return false;

    if (STRNEQ(str + len - suffixlen, suffix))
        return false;

    str[len - suffixlen] = '\0';

    return true;
}

bool
virStringMatchesNameSuffix(const char *file,
                           const char *name,
                           const char *suffix)
{
    int filelen = strlen(file);
    int namelen = strlen(name);
    int suffixlen = strlen(suffix);

    if (filelen == (namelen + suffixlen) &&
        STREQLEN(file, name, namelen) &&
        STREQ(file + namelen, suffix))
        return true;
    else
        return false;
}

/**
 * virStringStripIPv6Brackets:
 * @str: the string to strip
 *
 * Modify the string in-place to remove the leading and closing brackets
 * from an IPv6 address.
 */
void
virStringStripIPv6Brackets(char *str)
{
    size_t len;

    if (!str)
        return;

    len = strlen(str);
    if (str[0] == '[' && str[len - 1] == ']' && strchr(str, ':')) {
        memmove(&str[0], &str[1], len - 2);
        str[len - 2] = '\0';
    }
}


/**
 * virStringHasChars:
 * @str: string to look for chars in
 * @chars: chars to find in string @str
 *
 * Returns true if @str contains any of the chars in @chars.
 */
bool
virStringHasChars(const char *str,
                  const char *chars)
{
    if (!str)
        return false;

    return str[strcspn(str, chars)] != '\0';
}


static const char control_chars[] =
    "\x01\x02\x03\x04\x05\x06\x07"
    "\x08" /* \t \n */ "\x0B\x0C" /* \r */ "\x0E\x0F"
    "\x10\x11\x12\x13\x14\x15\x16\x17"
    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";

bool
virStringHasControlChars(const char *str)
{
    return virStringHasChars(str, control_chars);
}


/**
 * virStringStripControlChars:
 * @str: the string to strip
 *
 * Modify the string in-place to remove the control characters
 * in the interval: [0x01, 0x20)
 */
void
virStringStripControlChars(char *str)
{
    size_t len, i, j;

    if (!str)
        return;

    len = strlen(str);
    for (i = 0, j = 0; i < len; i++) {
        if (strchr(control_chars, str[i]))
            continue;

        str[j++] = str[i];
    }
    str[j] = '\0';
}

/**
 * virStringFilterChars:
 * @str: the string to strip
 * @valid: the valid characters for the string
 *
 * Modify the string in-place to remove the characters that aren't
 * in the list of valid ones.
 */
void
virStringFilterChars(char *str, const char *valid)
{
    size_t len, i, j;

    if (!str)
        return;

    len = strlen(str);
    for (i = 0, j = 0; i < len; i++) {
        if (strchr(valid, str[i]))
            str[j++] = str[i];
    }
    str[j] = '\0';
}

/**
 * virStringToUpper:
 * @src string to capitalize
 * @dst: where to store the new capitalized string
 *
 * Capitalize the string with replacement of all '-' characters for '_'
 * characters. Caller frees the result.
 *
 * Returns 0 if src is NULL, 1 if capitalization was successful, -1 on failure.
 */
int
virStringToUpper(char **dst, const char *src)
{
    char *cap = NULL;
    size_t i;

    if (!src)
        return 0;

    if (VIR_ALLOC_N(cap, strlen(src) + 1) < 0)
        return -1;

    for (i = 0; src[i]; i++) {
        cap[i] = c_toupper(src[i]);
        if (cap[i] == '-')
            cap[i] = '_';
    }

    *dst = cap;
    return 1;
}


/**
 * virStringIsPrintable:
 *
 * Returns true @str contains only printable characters.
 */
bool
virStringIsPrintable(const char *str)
{
    size_t i;

    for (i = 0; str[i]; i++)
        if (!c_isprint(str[i]))
            return false;

    return true;
}


/**
 * virBufferIsPrintable:
 *
 * Returns true if @buf of @buflen contains only printable characters
 */
bool
virStringBufferIsPrintable(const uint8_t *buf,
                           size_t buflen)
{
    size_t i;

    for (i = 0; i < buflen; i++)
        if (!c_isprint(buf[i]))
            return false;

    return true;
}


/**
 * virStringEncodeBase64:
 * @buf: buffer of bytes to encode
 * @buflen: number of bytes to encode
 *
 * Encodes @buf to base 64 and returns the resulting string. The caller is
 * responsible for freeing the result.
 */
char *
virStringEncodeBase64(const uint8_t *buf, size_t buflen)
{
    char *ret;

    base64_encode_alloc((const char *) buf, buflen, &ret);
    if (!ret)
        abort();

    return ret;
}

/**
 * virStringTrimOptionalNewline:
 * @str: the string to modify in-place
 *
 * Modify @str to remove a single '\n' character
 * from its end, if one exists.
 */
void virStringTrimOptionalNewline(char *str)
{
    size_t len = strlen(str);

    if (!len)
        return;

    if (str[len - 1] == '\n')
        str[len - 1] = '\0';
}


/**
 * virStringParsePort:
 * @str: port number to parse
 * @port: pointer to parse port into
 *
 * Parses a string representation of a network port and validates it. Returns
 * 0 on success and -1 on error.
 */
int
virStringParsePort(const char *str,
                   unsigned int *port)
{
    unsigned int p = 0;

    *port = 0;

    if (!str)
        return 0;

    if (virStrToLong_uip(str, NULL, 10, &p) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("failed to parse port number '%s'"), str);
        return -1;
    }

    if (p > UINT16_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("port '%s' out of range"), str);
        return -1;
    }

    *port = p;

    return 0;
}


/**
 * virStringParseYesNo:
 * @str: "yes|no" to parse, must not be NULL.
 * @result: pointer to the boolean result of @str conversion
 *
 * Parses a "yes|no" string and converts it into a boolean.
 *
 * Returns 0 on success and -1 on error.
 */
int virStringParseYesNo(const char *str, bool *result)
{
    if (STREQ(str, "yes"))
        *result = true;
    else if (STREQ(str, "no"))
        *result = false;
    else
        return -1;

    return 0;
}
