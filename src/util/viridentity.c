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

typedef enum {
      VIR_IDENTITY_ATTR_USER_NAME,
      VIR_IDENTITY_ATTR_UNIX_USER_ID,
      VIR_IDENTITY_ATTR_GROUP_NAME,
      VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
      VIR_IDENTITY_ATTR_PROCESS_ID,
      VIR_IDENTITY_ATTR_PROCESS_TIME,
      VIR_IDENTITY_ATTR_SASL_USER_NAME,
      VIR_IDENTITY_ATTR_X509_DISTINGUISHED_NAME,
      VIR_IDENTITY_ATTR_SELINUX_CONTEXT,

      VIR_IDENTITY_ATTR_LAST,
} virIdentityAttrType;

struct _virIdentity {
    virObject parent;

    char *attrs[VIR_IDENTITY_ATTR_LAST];
};

static virClassPtr virIdentityClass;
static virThreadLocal virIdentityCurrent;

static void virIdentityDispose(void *obj);

static int virIdentityOnceInit(void)
{
    if (!VIR_CLASS_NEW(virIdentity, virClassForObject()))
        return -1;

    if (virThreadLocalInit(&virIdentityCurrent,
                           (virThreadLocalCleanup)virObjectUnref) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot initialize thread local for current identity"));
        return -1;
    }

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virIdentity);

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

    if (virThreadLocalSet(&virIdentityCurrent,
                          virObjectRef(ident)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to set thread local identity"));
        virObjectUnref(ident);
        return -1;
    }

    virObjectUnref(old);

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
    VIR_AUTOFREE(char *) username = NULL;
    VIR_AUTOFREE(char *) groupname = NULL;
    unsigned long long startTime;
    virIdentityPtr ret = NULL;
#if WITH_SELINUX
    security_context_t con;
#endif

    if (!(ret = virIdentityNew()))
        goto error;

    if (virIdentitySetProcessID(ret, getpid()) < 0)
        goto error;

    if (virProcessGetStartTime(getpid(), &startTime) < 0)
        goto error;
    if (startTime != 0 &&
        virIdentitySetProcessTime(ret, startTime) < 0)
        goto error;

    if (!(username = virGetUserName(geteuid())))
        return ret;
    if (virIdentitySetUserName(ret, username) < 0)
        goto error;
    if (virIdentitySetUNIXUserID(ret, getuid()) < 0)
        goto error;

    if (!(groupname = virGetGroupName(getegid())))
        return ret;
    if (virIdentitySetGroupName(ret, groupname) < 0)
        goto error;
    if (virIdentitySetUNIXGroupID(ret, getgid()) < 0)
        goto error;

#if WITH_SELINUX
    if (is_selinux_enabled() > 0) {
        if (getcon(&con) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to lookup SELinux process context"));
            return ret;
        }
        if (virIdentitySetSELinuxContext(ret, con) < 0) {
            freecon(con);
            goto error;
        }
        freecon(con);
    }
#endif

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
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
static int
virIdentitySetAttr(virIdentityPtr ident,
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
static int
virIdentityGetAttr(virIdentityPtr ident,
                   unsigned int attr,
                   const char **value)
{
    VIR_DEBUG("ident=%p attribute=%d value=%p", ident, attr, value);

    *value = ident->attrs[attr];

    return 0;
}


int virIdentityGetUserName(virIdentityPtr ident,
                           const char **username)
{
    return virIdentityGetAttr(ident,
                              VIR_IDENTITY_ATTR_USER_NAME,
                              username);
}


int virIdentityGetUNIXUserID(virIdentityPtr ident,
                             uid_t *uid)
{
    int val;
    const char *userid;

    *uid = -1;
    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_USER_ID,
                           &userid) < 0)
        return -1;

    if (!userid)
        return -1;

    if (virStrToLong_i(userid, NULL, 10, &val) < 0)
        return -1;

    *uid = (uid_t)val;

    return 0;
}

int virIdentityGetGroupName(virIdentityPtr ident,
                            const char **groupname)
{
    return virIdentityGetAttr(ident,
                              VIR_IDENTITY_ATTR_GROUP_NAME,
                              groupname);
}


int virIdentityGetUNIXGroupID(virIdentityPtr ident,
                              gid_t *gid)
{
    int val;
    const char *groupid;

    *gid = -1;
    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
                           &groupid) < 0)
        return -1;

    if (!groupid)
        return -1;

    if (virStrToLong_i(groupid, NULL, 10, &val) < 0)
        return -1;

    *gid = (gid_t)val;

    return 0;
}


int virIdentityGetProcessID(virIdentityPtr ident,
                            pid_t *pid)
{
    unsigned long long val;
    const char *processid;

    *pid = 0;
    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_PROCESS_ID,
                           &processid) < 0)
        return -1;

    if (!processid)
        return -1;

    if (virStrToLong_ull(processid, NULL, 10, &val) < 0)
        return -1;

    *pid = (pid_t)val;

    return 0;
}


int virIdentityGetProcessTime(virIdentityPtr ident,
                              unsigned long long *timestamp)
{
    const char *processtime;
    if (virIdentityGetAttr(ident,
                           VIR_IDENTITY_ATTR_PROCESS_TIME,
                           &processtime) < 0)
        return -1;

    if (!processtime)
        return -1;

    if (virStrToLong_ull(processtime, NULL, 10, timestamp) < 0)
        return -1;

    return 0;
}


int virIdentityGetSASLUserName(virIdentityPtr ident,
                               const char **username)
{
    return virIdentityGetAttr(ident,
                              VIR_IDENTITY_ATTR_SASL_USER_NAME,
                              username);
}


int virIdentityGetX509DName(virIdentityPtr ident,
                            const char **dname)
{
    return virIdentityGetAttr(ident,
                              VIR_IDENTITY_ATTR_X509_DISTINGUISHED_NAME,
                              dname);
}


int virIdentityGetSELinuxContext(virIdentityPtr ident,
                                 const char **context)
{
    return virIdentityGetAttr(ident,
                              VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                              context);
}


int virIdentitySetUserName(virIdentityPtr ident,
                           const char *username)
{
    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_USER_NAME,
                              username);
}


int virIdentitySetUNIXUserID(virIdentityPtr ident,
                             uid_t uid)
{
    VIR_AUTOFREE(char *) val = NULL;

    if (virAsprintf(&val, "%d", (int)uid) < 0)
        return -1;

    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_UNIX_USER_ID,
                              val);
}


int virIdentitySetGroupName(virIdentityPtr ident,
                            const char *groupname)
{
    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_GROUP_NAME,
                              groupname);
}


int virIdentitySetUNIXGroupID(virIdentityPtr ident,
                              gid_t gid)
{
    VIR_AUTOFREE(char *) val = NULL;

    if (virAsprintf(&val, "%d", (int)gid) < 0)
        return -1;

    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
                              val);
}


int virIdentitySetProcessID(virIdentityPtr ident,
                            pid_t pid)
{
    VIR_AUTOFREE(char *) val = NULL;

    if (virAsprintf(&val, "%lld", (long long) pid) < 0)
        return -1;

    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_PROCESS_ID,
                              val);
}


int virIdentitySetProcessTime(virIdentityPtr ident,
                              unsigned long long timestamp)
{
    VIR_AUTOFREE(char *) val = NULL;

    if (virAsprintf(&val, "%llu", timestamp) < 0)
        return -1;

    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_PROCESS_TIME,
                              val);
}



int virIdentitySetSASLUserName(virIdentityPtr ident,
                               const char *username)
{
    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_SASL_USER_NAME,
                              username);
}


int virIdentitySetX509DName(virIdentityPtr ident,
                            const char *dname)
{
    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_X509_DISTINGUISHED_NAME,
                              dname);
}


int virIdentitySetSELinuxContext(virIdentityPtr ident,
                                 const char *context)
{
    return virIdentitySetAttr(ident,
                              VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                              context);
}
