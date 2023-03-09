/*
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virerror.h"
#include "virlog.h"
#include "virhostuptime.h"

#include "security_util.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_util");

/* There are four namespaces available on Linux (xattr(7)):
 *
 *  user - can be modified by anybody,
 *  system - used by ACLs
 *  security - used by SELinux
 *  trusted - accessibly by CAP_SYS_ADMIN processes only
 *
 * Looks like the last one is way to go.
 * Unfortunately, FreeBSD only supports:
 *
 *  user - can be modified by anybody,
 *  system - accessible by CAP_SYS_ADMIN processes only
 *
 * Note that 'system' on FreeBSD corresponds to 'trusted' on
 * Linux. So far the only point where FreeBSD and Linux can meet
 * is NFS which still doesn't support XATTRs. Therefore we can
 * use different namespace on each system. If NFS gains support
 * for XATTRs then we have to find a way to deal with the
 * different namespaces. But that is a problem for future me.
 */
#if defined(__linux__)
# define XATTR_NAMESPACE "trusted"
#elif defined(__FreeBSD__)
# define XATTR_NAMESPACE "system"
#endif

static char *
virSecurityGetAttrName(const char *name G_GNUC_UNUSED)
{
    char *ret = NULL;
#ifdef XATTR_NAMESPACE
    ret = g_strdup_printf(XATTR_NAMESPACE".libvirt.security.%s", name);
#else
    errno = ENOSYS;
    virReportSystemError(errno, "%s",
                         _("Extended attributes are not supported on this system"));
#endif
    return ret;
}


static char *
virSecurityGetRefCountAttrName(const char *name G_GNUC_UNUSED)
{
    char *ret = NULL;
#ifdef XATTR_NAMESPACE
    ret = g_strdup_printf(XATTR_NAMESPACE".libvirt.security.ref_%s", name);
#else
    errno = ENOSYS;
    virReportSystemError(errno, "%s",
                         _("Extended attributes are not supported on this system"));
#endif
    return ret;
}


#ifdef XATTR_NAMESPACE
static char *
virSecurityGetTimestampAttrName(const char *name)
{
    return g_strdup_printf(XATTR_NAMESPACE ".libvirt.security.timestamp_%s",
                           name);
}
#else /* !XATTR_NAMESPACE */
static char *
virSecurityGetTimestampAttrName(const char *name G_GNUC_UNUSED)
{
    errno = ENOSYS;
    virReportSystemError(errno, "%s",
                         _("Extended attributes are not supported on this system"));
    return NULL;
}
#endif /* !XATTR_NAMESPACE */


bool
virSecurityXATTRNamespaceDefined(void)
{
#ifdef XATTR_NAMESPACE
    return true;
#else
    return false;
#endif
}


static char *
virSecurityGetTimestamp(void)
{
    unsigned long long boottime = 0;

    if (virHostGetBootTime(&boottime) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get host boot time"));
        return NULL;
    }

    return g_strdup_printf("%llu", boottime);
}


/**
 * virSecurityValidateTimestamp:
 * @name: security driver name
 * @path: file name
 *
 * Check if remembered label on @path for security driver @name
 * is valid, i.e. the label has been set since the last boot. If
 * the label was set in previous runs, all XATTRs related to
 * @name are removed so that clean slate is restored.
 *
 * This is done having extra attribute timestamp_$SECDRIVER which
 * contains the host boot time. Its value is then compared to
 * actual host boot time. If these two values don't match then
 * XATTRs are considered as stale and thus invalid.
 *
 * In ideal world, where there network file systems have XATTRs
 * using plain host boot time is not enough as it may lead to a
 * situation where a freshly started host sees XATTRs, sees the
 * timestamp put there by some longer running host and considers
 * the XATTRs invalid. Well, there is not an easy way out. We
 * would need to somehow check if the longer running host is
 * still there and uses the @path (how?).
 * Fortunately, there is only one network file system which
 * supports XATTRs currently (GlusterFS via FUSE) and it is used
 * so rarely that it's almost a corner case.
 * The worst thing that happens there is that we remove XATTRs
 * and thus return @path to the default label for $SECDRIVER.
 *
 * Returns: 0 if remembered label is valid,
 *          1 if remembered label was not valid,
 *         -2 if underlying file system doesn't support XATTRs,
 *         -1 otherwise.
 */
static int
virSecurityValidateTimestamp(const char *name,
                             const char *path)
{
    g_autofree char *expected_timestamp = NULL;
    g_autofree char *timestamp_name = NULL;
    g_autofree char *value = NULL;

    if (!(expected_timestamp = virSecurityGetTimestamp()) ||
        !(timestamp_name = virSecurityGetTimestampAttrName(name)))
        return -1;

    errno = 0;
    if (virFileGetXAttrQuiet(path, timestamp_name, &value) < 0) {
        if (errno == ENOSYS || errno == ENOTSUP) {
            return -2;
        } else if (errno != ENODATA) {
            virReportSystemError(errno,
                                 _("Unable to get XATTR %1$s on %2$s"),
                                 timestamp_name,
                                 path);
            return -1;
        }

        /* Timestamp is missing. We could continue and claim a valid timestamp.
         * But then we would never remove stale XATTRs. Therefore, claim it
         * invalid and have the code below remove all XATTRs. This of course
         * means that we will not restore the original owner, but the plus side
         * is that we reset refcounter which will represent the true state.
         */
    }

    if (STREQ_NULLABLE(value, expected_timestamp)) {
        VIR_DEBUG("XATTRs on %s secdriver=%s are valid", path, name);
        return 0;
    }

    VIR_WARN("Invalid XATTR timestamp detected on %s secdriver=%s", path, name);

    if (virSecurityMoveRememberedLabel(name, path, NULL) < 0)
        return -1;

    return 1;
}


static int
virSecurityAddTimestamp(const char *name,
                        const char *path)
{
    g_autofree char *timestamp_name = NULL;
    g_autofree char *timestamp_value = NULL;

    if (!(timestamp_value = virSecurityGetTimestamp()) ||
        !(timestamp_name = virSecurityGetTimestampAttrName(name)))
        return -1;

    return virFileSetXAttr(path, timestamp_name, timestamp_value);
}


static int
virSecurityRemoveTimestamp(const char *name,
                           const char *path)
{
    g_autofree char *timestamp_name = NULL;

    if (!(timestamp_name = virSecurityGetTimestampAttrName(name)))
        return -1;

    if (virFileRemoveXAttr(path, timestamp_name) < 0 && errno != ENOENT)
        return -1;

    return 0;
}


/**
 * virSecurityGetRememberedLabel:
 * @name: security driver name
 * @path: file name
 * @label: label
 *
 * For given @path and security driver (@name) fetch remembered
 * @label. The caller must not restore label if an error is
 * indicated or if @label is NULL upon return.
 *
 * The idea is that the first time
 * virSecuritySetRememberedLabel() is called over @path the
 * @label is recorded and refcounter is set to 1. Each subsequent
 * call to virSecuritySetRememberedLabel() increases the counter.
 * Counterpart to this is virSecurityGetRememberedLabel() which
 * decreases the counter and reads the @label only if the counter
 * reached value of zero. For any other call (i.e. when the
 * counter is not zero), virSecurityGetRememberedLabel() sets
 * @label to NULL (to notify the caller that the refcount is not
 * zero) and returns zero.
 *
 * Returns: 0 on success,
 *         -2 if underlying file system doesn't support XATTRs,
 *         -1 otherwise (with error reported)
 */
int
virSecurityGetRememberedLabel(const char *name,
                              const char *path,
                              char **label)
{
    g_autofree char *ref_name = NULL;
    g_autofree char *attr_name = NULL;
    g_autofree char *value = NULL;
    unsigned int refcount = 0;

    *label = NULL;

    if (!(ref_name = virSecurityGetRefCountAttrName(name))) {
        if (errno == ENOSYS)
            return -2;
        return -1;
    }

    if (virFileGetXAttrQuiet(path, ref_name, &value) < 0) {
        if (errno == ENOSYS || errno == ENODATA || errno == ENOTSUP)
            return -2;

        virReportSystemError(errno,
                             _("Unable to get XATTR %1$s on %2$s"),
                             ref_name,
                             path);
        return -1;
    }

    if (value) {
        int rc;

        /* Do this after we've tried to get refcounter to ensure underlying FS
         * supports XATTRs and @path has refcounter attribute set, because
         * validator might throws a warning. */
        if ((rc = virSecurityValidateTimestamp(name, path)) < 0)
            return rc;

        /* Invalid label is like a non-existent one */
        if (rc == 1)
            return -2;
    }

    if (virStrToLong_ui(value, NULL, 10, &refcount) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed refcount %1$s on %2$s"),
                       value, path);
        return -1;
    }

    VIR_FREE(value);

    refcount--;

    if (refcount > 0) {
        value = g_strdup_printf("%u", refcount);

        if (virFileSetXAttr(path, ref_name, value) < 0)
            return -1;
    } else {
        if (virFileRemoveXAttr(path, ref_name) < 0)
            return -1;

        if (!(attr_name = virSecurityGetAttrName(name)))
            return -1;

        if (virFileGetXAttr(path, attr_name, label) < 0)
            return -1;

        if (virFileRemoveXAttr(path, attr_name) < 0)
            return -1;

        if (virSecurityRemoveTimestamp(name, path) < 0)
            return -1;
    }

    return 0;
}


/**
 * virSecuritySetRememberedLabel:
 * @name: security driver name
 * @path: file name
 * @label: label
 *
 * For given @path and security driver (@name), if called the
 * first time over @path, set the @label to remember (i.e. the
 * original owner of the @path). Any subsequent call over @path
 * will increment refcounter. It is strongly recommended that the
 * caller checks for the return value and if it is greater than 1
 * (meaning that some domain is already using @path) the current
 * label is required instead of setting a new one.
 *
 * See also virSecurityGetRememberedLabel.
 *
 * Returns: the new refcount value on success,
 *         -2 if underlying file system doesn't support XATTRs,
 *         -1 otherwise (with error reported)
 */
int
virSecuritySetRememberedLabel(const char *name,
                              const char *path,
                              const char *label)
{
    g_autofree char *ref_name = NULL;
    g_autofree char *attr_name = NULL;
    g_autofree char *value = NULL;
    unsigned int refcount = 0;

    if (!(ref_name = virSecurityGetRefCountAttrName(name))) {
        if (errno == ENOSYS)
            return -2;
        return -1;
    }

    if (virFileGetXAttrQuiet(path, ref_name, &value) < 0) {
        if (errno == ENOSYS || errno == ENOTSUP) {
            return -2;
        } else if (errno != ENODATA) {
            virReportSystemError(errno,
                                 _("Unable to get XATTR %1$s on %2$s"),
                                 ref_name,
                                 path);
            return -1;
        }
    }

    if (value) {
        int rc;

        /* Do this after we've tried to get refcounter to ensure underlying FS
         * supports XATTRs and @path has refcounter attribute set, because
         * validator might throws a warning. */
        if ((rc = virSecurityValidateTimestamp(name, path)) < 0)
            return rc;

        /* Invalid label is like a non-existent one */
        if (rc == 1)
            VIR_FREE(value);
    }

    if (value &&
        virStrToLong_ui(value, NULL, 10, &refcount) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed refcount %1$s on %2$s"),
                       value, path);
        return -1;
    }

    VIR_FREE(value);

    refcount++;

    if (refcount == 1) {
        if (!(attr_name = virSecurityGetAttrName(name)))
            return -1;

        if (virFileSetXAttr(path, attr_name, label) < 0)
            return -1;

        if (virSecurityAddTimestamp(name, path) < 0)
            return -1;
    }

    value = g_strdup_printf("%u", refcount);

    if (virFileSetXAttr(path, ref_name, value) < 0)
        return -1;

    return refcount;
}


/**
 * virSecurityMoveRememberedLabel:
 * @name: security driver name
 * @src: source file
 * @dst: destination file
 *
 * For given security driver @name, move all XATTRs related to seclabel
 * remembering from @src to @dst. However, if @dst is NULL, then XATTRs
 * are just removed from @src.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
virSecurityMoveRememberedLabel(const char *name,
                               const char *src,
                               const char *dst)
{
    g_autofree char *ref_name = NULL;
    g_autofree char *ref_value = NULL;
    g_autofree char *attr_name = NULL;
    g_autofree char *attr_value = NULL;
    g_autofree char *timestamp_name = NULL;
    g_autofree char *timestamp_value = NULL;

    if (!(ref_name = virSecurityGetRefCountAttrName(name)) ||
        !(attr_name = virSecurityGetAttrName(name)) ||
        !(timestamp_name = virSecurityGetTimestampAttrName(name))) {
        if (errno == ENOSYS)
            return -2;
        return -1;
    }

    if (virFileGetXAttrQuiet(src, ref_name, &ref_value) < 0) {
        if (errno == ENOSYS || errno == ENOTSUP) {
            return -2;
        } else if (errno != ENODATA) {
            virReportSystemError(errno,
                                 _("Unable to get XATTR %1$s on %2$s"),
                                 ref_name, src);
            return -1;
        }
    }

    if (virFileGetXAttrQuiet(src, attr_name, &attr_value) < 0) {
        if (errno == ENOSYS || errno == ENOTSUP) {
            return -2;
        } else if (errno != ENODATA) {
            virReportSystemError(errno,
                                 _("Unable to get XATTR %1$s on %2$s"),
                                 attr_name, src);
            return -1;
        }
    }

    if (virFileGetXAttrQuiet(src, timestamp_name, &timestamp_value) < 0) {
        if (errno == ENOSYS || errno == ENOTSUP) {
            return -2;
        } else if (errno != ENODATA) {
            virReportSystemError(errno,
                                 _("Unable to get XATTR %1$s on %2$s"),
                                 attr_name, src);
            return -1;
        }
    }

    if (ref_value &&
        virFileRemoveXAttr(src, ref_name) < 0) {
        return -1;
    }

    if (attr_value &&
        virFileRemoveXAttr(src, attr_name) < 0) {
        return -1;
    }

    if (timestamp_value &&
        virFileRemoveXAttr(src, timestamp_name) < 0) {
        return -1;
    }

    if (dst) {
        if (ref_value &&
            virFileSetXAttr(dst, ref_name, ref_value) < 0) {
            return -1;
        }

        if (attr_value &&
            virFileSetXAttr(dst, attr_name, attr_value) < 0) {
            ignore_value(virFileRemoveXAttr(dst, ref_name));
            return -1;
        }

        if (timestamp_value &&
            virFileSetXAttr(dst, timestamp_name, timestamp_value) < 0) {
            ignore_value(virFileRemoveXAttr(dst, ref_name));
            ignore_value(virFileRemoveXAttr(dst, attr_name));
            return -1;
        }
    }

    return 0;
}
