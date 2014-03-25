/*
 * viridentity.c: helper APIs for managing user identities
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <unistd.h>
#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "internal.h"
#include "viralloc.h"
#include "virerror.h"
#include "viridentity.h"
#include "virlog.h"
#include "virobject.h"
#include "virthread.h"
#include "virutil.h"
#include "virstring.h"
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_IDENTITY

VIR_LOG_INIT("util.identity");

struct _virIdentity {
    virObject parent;

    char *attrs[VIR_IDENTITY_ATTR_LAST];
};

static virClassPtr virIdentityClass;
static virThreadLocal virIdentityCurrent;

static void virIdentityDispose(void *obj);

static int virIdentityOnceInit(void)
{
    if (!(virIdentityClass = virClassNew(virClassForObject(),
                                         "virIdentity",
                                         sizeof(virIdentity),
                                         virIdentityDispose)))
        return -1;

    if (virThreadLocalInit(&virIdentityCurrent,
                           (virThreadLocalCleanup)virObjectUnref) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot initialize thread local for current identity"));
        return -1;
    }

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virIdentity)

/**
 * virIdentityGetCurrent:
 *
 * Get the current identity associated with this thread. The
 * caller will own a reference to the returned identity, but
 * must not modify the object in any way, other than to
 * release the reference when done with virObjectUnref
 *
 * Returns: a reference to the current identity, or NULL
 */
virIdentityPtr virIdentityGetCurrent(void)
{
    virIdentityPtr ident;

    if (virIdentityInitialize() < 0)
        return NULL;

    ident = virThreadLocalGet(&virIdentityCurrent);
    return virObjectRef(ident);
}


/**
 * virIdentitySetCurrent:
 *
 * Set the new identity to be associated with this thread.
 * The caller should not modify the passed identity after
 * it has been set, other than to release its own reference.
 *
 * Returns 0 on success, or -1 on error
 */
int virIdentitySetCurrent(virIdentityPtr ident)
{
    virIdentityPtr old;

    if (virIdentityInitialize() < 0)
        return -1;

    old = virThreadLocalGet(&virIdentityCurrent);
    virObjectUnref(old);

    if (virThreadLocalSet(&virIdentityCurrent,
                          virObjectRef(ident)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to set thread local identity"));
        return -1;
    }

    return 0;
}


/**
 * virIdentityGetSystem:
 *
 * Returns an identity that represents the system itself.
 * This is the identity that the process is running as
 *
 * Returns a reference to the system identity, or NULL
 */
virIdentityPtr virIdentityGetSystem(void)
{
    char *username = NULL;
    char *userid = NULL;
    char *groupname = NULL;
    char *groupid = NULL;
    char *seccontext = NULL;
    virIdentityPtr ret = NULL;
#if WITH_SELINUX
    security_context_t con;
#endif
    char *processid = NULL;
    unsigned long long timestamp;
    char *processtime = NULL;

    if (virAsprintf(&processid, "%llu",
                    (unsigned long long)getpid()) < 0)
        goto cleanup;

    if (virProcessGetStartTime(getpid(), &timestamp) < 0)
        goto cleanup;

    if (timestamp != 0 &&
        virAsprintf(&processtime, "%llu", timestamp) < 0)
        goto cleanup;

    if (!(username = virGetUserName(geteuid())))
        goto cleanup;
    if (virAsprintf(&userid, "%d", (int)geteuid()) < 0)
        goto cleanup;

    if (!(groupname = virGetGroupName(getegid())))
        goto cleanup;
    if (virAsprintf(&groupid, "%d", (int)getegid()) < 0)
        goto cleanup;

#if WITH_SELINUX
    if (is_selinux_enabled() > 0) {
        if (getcon(&con) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to lookup SELinux process context"));
            goto cleanup;
        }
        if (VIR_STRDUP(seccontext, con) < 0) {
            freecon(con);
            goto cleanup;
        }
        freecon(con);
    }
#endif

    if (!(ret = virIdentityNew()))
        goto cleanup;

    if (virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           username) < 0)
        goto error;
    if (virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_USER_ID,
                           userid) < 0)
        goto error;
    if (virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           groupname) < 0)
        goto error;
    if (virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
                           groupid) < 0)
        goto error;
    if (seccontext &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                           seccontext) < 0)
        goto error;
    if (virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_PROCESS_ID,
                           processid) < 0)
        goto error;
    if (processtime &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_PROCESS_TIME,
                           processtime) < 0)
        goto error;

 cleanup:
    VIR_FREE(username);
    VIR_FREE(userid);
    VIR_FREE(groupname);
    VIR_FREE(groupid);
    VIR_FREE(seccontext);
    VIR_FREE(processid);
    VIR_FREE(processtime);
    return ret;

 error:
    virObjectUnref(ret);
    ret = NULL;
    goto cleanup;
}


/**
 * virIdentityNew:
 *
 * Creates a new empty identity object. After creating, one or
 * more identifying attributes should be set on the identity.
 *
 * Returns: a new empty identity
 */
virIdentityPtr virIdentityNew(void)
{
    virIdentityPtr ident;

    if (virIdentityInitialize() < 0)
        return NULL;

    if (!(ident = virObjectNew(virIdentityClass)))
        return NULL;

    return ident;
}


static void virIdentityDispose(void *object)
{
    virIdentityPtr ident = object;
    size_t i;

    for (i = 0; i < VIR_IDENTITY_ATTR_LAST; i++)
        VIR_FREE(ident->attrs[i]);
}


/**
 * virIdentitySetAttr:
 * @ident: the identity to modify
 * @attr: the attribute type to set
 * @value: the identifying value to associate with @attr
 *
 * Sets an identifying attribute @attr on @ident. Each
 * @attr type can only be set once.
 *
 * Returns: 0 on success, or -1 on error
 */
int virIdentitySetAttr(virIdentityPtr ident,
                       unsigned int attr,
                       const char *value)
{
    int ret = -1;
    VIR_DEBUG("ident=%p attribute=%u value=%s", ident, attr, value);

    if (ident->attrs[attr]) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                        _("Identity attribute is already set"));
        goto cleanup;
    }

    if (VIR_STRDUP(ident->attrs[attr], value) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


/**
 * virIdentityGetAttr:
 * @ident: the identity to query
 * @attr: the attribute to read
 * @value: filled with the attribute value
 *
 * Fills @value with a pointer to the value associated
 * with the identifying attribute @attr in @ident. If
 * @attr is not set, then it will simply be initialized
 * to NULL and considered as a successful read
 *
 * Returns 0 on success, -1 on error
 */
int virIdentityGetAttr(virIdentityPtr ident,
                       unsigned int attr,
                       const char **value)
{
    VIR_DEBUG("ident=%p attribute=%d value=%p", ident, attr, value);

    *value = ident->attrs[attr];

    return 0;
}


/**
 * virIdentityIsEqual:
 * @identA: the first identity
 * @identB: the second identity
 *
 * Compares every attribute in @identA and @identB
 * to determine if they refer to the same identity
 *
 * Returns true if they are equal, false if not equal
 */
bool virIdentityIsEqual(virIdentityPtr identA,
                        virIdentityPtr identB)
{
    bool ret = false;
    size_t i;
    VIR_DEBUG("identA=%p identB=%p", identA, identB);

    for (i = 0; i < VIR_IDENTITY_ATTR_LAST; i++) {
        if (STRNEQ_NULLABLE(identA->attrs[i],
                            identB->attrs[i]))
            goto cleanup;
    }

    ret = true;
 cleanup:
    return ret;
}
