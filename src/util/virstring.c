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

#include <glib/gprintf.h>
#include <locale.h>
#ifdef WITH_XLOCALE_H
# include <xlocale.h>
#endif

#include "virstring.h"
#include "virthread.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.string");

/* Like strtol with C locale, but produce an "int" result, and check more carefully.
   Return 0 upon success;  return -1 to indicate failure.
   When END_PTR is NULL, the byte after the final valid digit must be NUL.
   Otherwise, it's like strtol and lets the caller check any suffix for
   validity.  This function is careful to return -1 when the string S
   represents a number that is not representable as an "int". */
int
virStrToLong_i(char const *s, char **end_ptr, int base, int *result)
{
    long long val;
    char *p;
    int err;

    errno = 0;
    val = g_ascii_strtoll(s, &p, base);
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
    unsigned long long val;
    char *p;
    bool err = false;

    errno = 0;
    val = g_ascii_strtoull(s, &p, base);

    /* This one's tricky.  We _want_ to allow "-1" as shorthand for
     * UINT_MAX regardless of whether long is 32-bit or 64-bit.  But
     * g_ascii_strtoull treats "-1" as ULLONG_MAX, and going from ullong back
     * to uint differs depending on the size of uint. */
    if (memchr(s, '-', p - s)) {
        if (-val > UINT_MAX)
            err = true;
        else
            val &= UINT_MAX;
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
    unsigned long long val;
    char *p;
    bool err = false;

    errno = 0;
    val = g_ascii_strtoull(s, &p, base);
    err = (memchr(s, '-', p - s) ||
           errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* virStrToLong_l is intentionally skipped, consider virStrToLong_ll instead */

/* Just like virStrToLong_i, above, but produce an "unsigned long"
 * value.  This version allows twos-complement wraparound of negative
 * numbers. */
int
virStrToLong_ul(char const *s, char **end_ptr, int base, unsigned long *result)
{
    unsigned long long val;
    char *p;
    bool err = false;

    errno = 0;
    val = g_ascii_strtoull(s, &p, base);

    /* This one's tricky.  We _want_ to allow "-1" as shorthand for
     * ULONG_MAX regardless of whether long is 32-bit or 64-bit.  But
     * g_ascii_strtoull treats "-1" as ULLONG_MAX, and going from ullong back
     * to ulong differs depending on the size of ulong. */
    if (memchr(s, '-', p - s)) {
        if (-val > ULONG_MAX)
            err = true;
        else
            val &= ULONG_MAX;
    }

    err |= (errno || (!end_ptr && *p) || p == s || (unsigned long) val != val);
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
    unsigned long long val;
    char *p;
    int err;

    errno = 0;
    val = g_ascii_strtoull(s, &p, base);
    err = (memchr(s, '-', p - s) ||
           errno || (!end_ptr && *p) || p == s || (unsigned long) val != val);
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
    val = g_ascii_strtoll(s, &p, base);
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
    val = g_ascii_strtoull(s, &p, base);
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
    val = g_ascii_strtoull(s, &p, base);
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
#if WITH_NEWLOCALE

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
virLocaleFixupRadix(char **strp G_GNUC_UNUSED)
{
}

#else /* !WITH_NEWLOCALE */

typedef int virLocale;

static int
virLocaleSetRaw(virLocale *oldlocale G_GNUC_UNUSED)
{
    return 0;
}

static void
virLocaleRevert(virLocale *oldlocale G_GNUC_UNUSED)
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

#endif /* !WITH_NEWLOCALE */


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
 * Returns: 0 on success, -1 otherwise.
 */
int
virDoubleToStr(char **strp, double number)
{
    virLocale oldlocale;

    if (virLocaleSetRaw(&oldlocale) < 0)
        return -1;

    *strp = g_strdup_printf("%lf", number);

    virLocaleRevert(&oldlocale);
    virLocaleFixupRadix(strp);

    return 0;
}


/**
 * virStrcpy:
 *
 * @dest: destination buffer
 * @src: source buffer
 * @destbytes: number of bytes the destination can accommodate
 *
 * Copies @src to @dest. @dest is guaranteed to be 'nul' terminated if
 * destbytes is 1 or more.
 *
 * Returns: 0 on success, -1 if @src doesn't fit into @dest and was truncated.
 */
int
virStrcpy(char *dest, const char *src, size_t destbytes)
{
    if (g_strlcpy(dest, src, destbytes) >= destbytes)
        return -1;

    return 0;
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

    while (g_ascii_isspace(*cur))
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

    while (g_ascii_isspace(*cur) || *cur == '\\')
        cur++;
    *str = cur;
}


/**
 * virSkipToDigit:
 * @str: pointer to the char pointer used
 *
 * Skip over any character that is not 0-9
 */
void
virSkipToDigit(const char **str)
{
    const char *cur = *str;

    while (*cur && !g_ascii_isdigit(*cur))
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
    while (end > str && g_ascii_isspace(end[-1]))
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
 * The @matches value should be freed with g_strfreev() when no longer
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
 *  g_strfreev(matches);
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
    g_autoptr(GRegex) regex = NULL;
    g_autoptr(GError) err = NULL;
    size_t nmatches = 0;
    ssize_t ret = -1;

    *matches = NULL;

    VIR_DEBUG("search '%s' for '%s'", str, regexp);

    regex = g_regex_new(regexp, 0, 0, &err);
    if (!regex) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %1$s"), err->message);
        return -1;
    }

    if (g_regex_get_capture_count(regex) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Regular expression '%1$s' must have exactly 1 match group, not %2$d"),
                       regexp, g_regex_get_capture_count(regex));
        goto cleanup;
    }

    /* '*matches' must always be NULL terminated in every iteration
     * of the loop, so start by allocating 1 element
     */
    VIR_EXPAND_N(*matches, nmatches, 1);

    while ((nmatches - 1) < max_matches) {
        g_autoptr(GMatchInfo) info = NULL;
        char *match;
        int endpos;

        if (!g_regex_match(regex, str, 0, &info))
            break;

        VIR_EXPAND_N(*matches, nmatches, 1);

        match = g_match_info_fetch(info, 1);

        VIR_DEBUG("Got '%s'", match);

        (*matches)[nmatches-2] = match;

        g_match_info_fetch_pos(info, 1, NULL, &endpos);
        str += endpos;
    }

    ret = nmatches - 1; /* don't count the trailing null */

 cleanup:
    if (ret < 0) {
        g_clear_pointer(matches, g_strfreev);
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
    g_autoptr(GRegex) regex = NULL;
    g_autoptr(GError) err = NULL;

    VIR_DEBUG("match '%s' for '%s'", str, regexp);

    regex = g_regex_new(regexp, 0, 0, &err);
    if (!regex) {
        VIR_WARN("Failed to compile regex %s", err->message);
        return false;
    }

    return g_regex_match(regex, str, 0, NULL);
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
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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

    cap = g_new0(char, strlen(src) + 1);

    for (i = 0; src[i]; i++) {
        cap[i] = g_ascii_toupper(src[i]);
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
        if (!g_ascii_isprint(str[i]))
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
        if (!g_ascii_isprint(buf[i]))
            return false;

    return true;
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
                       _("failed to parse port number '%1$s'"), str);
        return -1;
    }

    if (p > UINT16_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("port '%1$s' out of range"), str);
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


/**
 * virStringParseVersion:
 * @version: unsigned long long pointer to output the version number
 * @str: const char pointer to the version string
 * @allowMissing: true to treat 3 like 3.0.0, false to error out on
 * missing minor or micro
 *
 * Parse an unsigned version number from a version string. Expecting
 * 'major.minor.micro' format, ignoring an optional suffix.
 *
 * The major, minor and micro numbers are encoded into a single version number:
 *
 *   1000000 * major + 1000 * minor + micro
 *
 * Returns the 0 for success, -1 for error.
 */
int
virStringParseVersion(unsigned long long *version,
                      const char *str,
                      bool allowMissing)
{
    unsigned int major, minor = 0, micro = 0;
    char *tmp;

    if (virStrToLong_ui(str, &tmp, 10, &major) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &minor) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &micro) < 0)
        return -1;

    if (major > UINT_MAX / 1000000 || minor > 999 || micro > 999)
        return -1;

    *version = 1000000 * major + 1000 * minor + micro;

    return 0;
}
