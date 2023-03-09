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
#include <fcntl.h>
#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#define LIBVIRT_VIRIDENTITYPRIV_H_ALLOW

#include "internal.h"
#include "virerror.h"
#include "viridentitypriv.h"
#include "virlog.h"
#include "virrandom.h"
#include "virthread.h"
#include "virutil.h"
#include "virprocess.h"
#include "virtypedparam.h"
#include "virfile.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_IDENTITY

#define VIR_CONNECT_IDENTITY_SYSTEM_TOKEN "system.token"

VIR_LOG_INIT("util.identity");

struct _virIdentity {
    GObject parent;

    int nparams;
    int maxparams;
    virTypedParameterPtr params;
};

G_DEFINE_TYPE(virIdentity, vir_identity, G_TYPE_OBJECT)

static virThreadLocal virIdentityCurrent;
static char *systemToken;

static void virIdentityFinalize(GObject *obj);

static void virIdentityCurrentCleanup(void *ident)
{
    if (ident)
        g_object_unref(ident);
}

static int virIdentityOnceInit(void)
{
    if (virThreadLocalInit(&virIdentityCurrent,
                           virIdentityCurrentCleanup) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot initialize thread local for current identity"));
        return -1;
    }

    if (!(systemToken = virIdentityEnsureSystemToken()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virIdentity);

static void vir_identity_init(virIdentity *ident G_GNUC_UNUSED)
{
}

static void vir_identity_class_init(virIdentityClass *klass)
{
    GObjectClass *obj = G_OBJECT_CLASS(klass);

    obj->finalize = virIdentityFinalize;
}

/**
 * virIdentityGetCurrent:
 *
 * Get the current identity associated with this thread. The
 * caller will own a reference to the returned identity, but
 * must not modify the object in any way, other than to
 * release the reference when done with g_object_unref
 *
 * Returns: a reference to the current identity, or NULL
 */
virIdentity *virIdentityGetCurrent(void)
{
    virIdentity *ident;

    if (virIdentityInitialize() < 0)
        return NULL;

    ident = virThreadLocalGet(&virIdentityCurrent);
    if (ident)
        g_object_ref(ident);
    return ident;
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
int virIdentitySetCurrent(virIdentity *ident)
{
    virIdentity *old = NULL;

    if (virIdentityInitialize() < 0)
        return -1;

    old = virThreadLocalGet(&virIdentityCurrent);

    if (virThreadLocalSet(&virIdentityCurrent,
                          ident ? g_object_ref(ident) : NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to set thread local identity"));
        if (ident)
            g_object_unref(ident);
        return -1;
    }

    if (old)
        g_object_unref(old);
    return 0;
}


/**
 * virIdentityElevateCurrent:
 *
 * Set the new identity to be associated with this thread,
 * to an elevated copy of the current identity. The old
 * current identity is returned and should be released by
 * the caller when no longer required.
 *
 * Returns the previous identity, or NULL on error
 */
virIdentity *virIdentityElevateCurrent(void)
{
    g_autoptr(virIdentity) ident = virIdentityGetCurrent();
    const char *token;
    int rc;

    if (!ident) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No current identity to elevate"));
        return NULL;
    }

    if ((rc = virIdentityGetSystemToken(ident, &token)) < 0)
        return NULL;

    if (rc == 0) {
        g_autoptr(virIdentity) identel = virIdentityNewCopy(ident);

        if (virIdentitySetSystemToken(identel, systemToken) < 0)
            return NULL;

        if (virIdentitySetCurrent(identel) < 0)
            return NULL;
    }

    return g_steal_pointer(&ident);
}


void virIdentityRestoreHelper(virIdentity **identptr)
{
    virIdentity *ident = *identptr;

    if (ident != NULL) {
        virIdentitySetCurrent(ident);
        /* virIdentitySetCurrent() grabs its own reference.
         * We don't need ours anymore. */
        g_object_unref(ident);
    }
}

#define TOKEN_BYTES 16
#define TOKEN_STRLEN (TOKEN_BYTES * 2)

static char *
virIdentityConstructSystemTokenPath(void)
{
    g_autofree char *commondir = NULL;
    if (geteuid() == 0) {
        commondir = g_strdup(RUNSTATEDIR "/libvirt/common");
    } else {
        g_autofree char *rundir = virGetUserRuntimeDirectory();
        commondir = g_strdup_printf("%s/common", rundir);
    }

    if (g_mkdir_with_parents(commondir, 0700) < 0) {
        virReportSystemError(errno,
                             _("Cannot create daemon common directory '%1$s'"),
                             commondir);
        return NULL;
    }

    return g_strdup_printf("%s/system.token", commondir);
}


char *
virIdentityEnsureSystemToken(void)
{
    g_autofree char *tokenfile = virIdentityConstructSystemTokenPath();
    g_autofree char *token = NULL;
    VIR_AUTOCLOSE fd = -1;
    struct stat st;

    if (!tokenfile)
        return NULL;

    fd = open(tokenfile, O_RDWR|O_APPEND|O_CREAT, 0600);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("Unable to open system token %1$s"),
                             tokenfile);
        return NULL;
    }

    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno,
                             _("Failed to set close-on-exec flag '%1$s'"),
                             tokenfile);
        return NULL;
    }

    if (virFileLock(fd, false, 0, 1, true) < 0) {
        virReportSystemError(errno,
                             _("Failed to lock system token '%1$s'"),
                             tokenfile);
        return NULL;
    }

    if (fstat(fd, &st) < 0) {
        virReportSystemError(errno,
                             _("Failed to check system token '%1$s'"),
                             tokenfile);
        return NULL;
    }

    /* Ok, we're the first one here, so we must populate it */
    if (st.st_size == 0) {
        if (!(token = virRandomToken(TOKEN_BYTES))) {
            return NULL;
        }
        if (safewrite(fd, token, TOKEN_STRLEN) != TOKEN_STRLEN) {
            virReportSystemError(errno,
                                 _("Failed to write system token '%1$s'"),
                                 tokenfile);
            return NULL;
        }
    } else {
        if (virFileReadLimFD(fd, TOKEN_STRLEN, &token) < 0) {
            virReportSystemError(errno,
                                 _("Failed to read system token '%1$s'"),
                                 tokenfile);
            return NULL;
        }
        if (strlen(token) != TOKEN_STRLEN) {
            virReportSystemError(errno,
                                 _("System token in %1$s was corrupt"),
                                 tokenfile);
            return NULL;
        }
    }

    return g_steal_pointer(&token);
}


/**
 * virIdentityGetSystem:
 *
 * Returns an identity that represents the system itself.
 * This is the identity that the process is running as
 *
 * Returns a reference to the system identity, or NULL
 */
virIdentity *virIdentityGetSystem(void)
{
    g_autofree char *username = NULL;
    g_autofree char *groupname = NULL;
    unsigned long long startTime;
    g_autoptr(virIdentity) ret = virIdentityNew();
#if WITH_SELINUX
    char *con;
#endif
    g_autofree char *token = NULL;

    if (virIdentitySetProcessID(ret, getpid()) < 0)
        return NULL;

    if (virProcessGetStartTime(getpid(), &startTime) < 0)
        return NULL;
    if (startTime != 0 &&
        virIdentitySetProcessTime(ret, startTime) < 0)
        return NULL;

    if (!(username = virGetUserName(geteuid())))
        return ret;
    if (virIdentitySetUserName(ret, username) < 0)
        return NULL;
    if (virIdentitySetUNIXUserID(ret, getuid()) < 0)
        return NULL;

    if (!(groupname = virGetGroupName(getegid())))
        return ret;
    if (virIdentitySetGroupName(ret, groupname) < 0)
        return NULL;
    if (virIdentitySetUNIXGroupID(ret, getgid()) < 0)
        return NULL;

#if WITH_SELINUX
    if (is_selinux_enabled() > 0) {
        if (getcon(&con) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to lookup SELinux process context"));
            return NULL;
        }
        if (virIdentitySetSELinuxContext(ret, con) < 0) {
            freecon(con);
            return NULL;
        }
        freecon(con);
    }
#endif

    if (!(token = virIdentityEnsureSystemToken()))
        return NULL;

    if (virIdentitySetSystemToken(ret, token) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


/**
 * virIdentityIsCurrentElevated:
 *
 * Determine if the current identity has elevated privileges.
 * This indicates that it was invoked on behalf of the
 * user by a libvirt daemon.
 *
 * Returns: true if elevated
 */
int virIdentityIsCurrentElevated(void)
{
    g_autoptr(virIdentity) current = virIdentityGetCurrent();
    const char *currentToken = NULL;
    int rv;

    if (!current) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No current identity"));
        return -1;
    }

    rv = virIdentityGetSystemToken(current, &currentToken);
    if (rv <= 0)
        return rv;

    return STREQ_NULLABLE(currentToken, systemToken);
}

/**
 * virIdentityNew:
 *
 * Creates a new empty identity object. After creating, one or
 * more identifying attributes should be set on the identity.
 *
 * Returns: a new empty identity
 */
virIdentity *virIdentityNew(void)
{
    return VIR_IDENTITY(g_object_new(VIR_TYPE_IDENTITY, NULL));
}


/**
 * virIdentityNewCopy:
 *
 * Creates a new identity object that is a deep copy of an
 * existing identity.
 *
 * Returns: a copy of the source identity
 */
virIdentity *virIdentityNewCopy(virIdentity *src)
{
    g_autoptr(virIdentity) ident = virIdentityNew();

    virTypedParamsCopy(&ident->params, src->params, src->nparams);
    ident->nparams = src->nparams;
    ident->maxparams = src->nparams;

    return g_steal_pointer(&ident);
}


static void virIdentityFinalize(GObject *object)
{
    virIdentity *ident = VIR_IDENTITY(object);

    virTypedParamsFree(ident->params, ident->nparams);

    G_OBJECT_CLASS(vir_identity_parent_class)->finalize(object);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetUserName(virIdentity *ident,
                           const char **username)
{
    *username = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_USER_NAME,
                                   username);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetUNIXUserID(virIdentity *ident,
                             uid_t *uid)
{
    unsigned long long val;
    int rc;

    *uid = -1;
    rc = virTypedParamsGetULLong(ident->params,
                                 ident->nparams,
                                 VIR_CONNECT_IDENTITY_UNIX_USER_ID,
                                 &val);
    if (rc <= 0)
        return rc;

    *uid = (uid_t)val;

    return 1;
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetGroupName(virIdentity *ident,
                            const char **groupname)
{
    *groupname = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_GROUP_NAME,
                                   groupname);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetUNIXGroupID(virIdentity *ident,
                              gid_t *gid)
{
    unsigned long long val;
    int rc;

    *gid = -1;
    rc = virTypedParamsGetULLong(ident->params,
                                 ident->nparams,
                                 VIR_CONNECT_IDENTITY_UNIX_GROUP_ID,
                                 &val);
    if (rc <= 0)
        return rc;

    *gid = (gid_t)val;

    return 1;
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetProcessID(virIdentity *ident,
                            pid_t *pid)
{
    long long val;
    int rc;

    *pid = 0;
    rc = virTypedParamsGetLLong(ident->params,
                                ident->nparams,
                                VIR_CONNECT_IDENTITY_PROCESS_ID,
                                &val);
    if (rc <= 0)
        return rc;

    *pid = (pid_t)val;

    return 1;
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetProcessTime(virIdentity *ident,
                              unsigned long long *timestamp)
{
    *timestamp = 0;
    return virTypedParamsGetULLong(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_PROCESS_TIME,
                                   timestamp);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetSASLUserName(virIdentity *ident,
                               const char **username)
{
    *username = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_SASL_USER_NAME,
                                   username);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetX509DName(virIdentity *ident,
                            const char **dname)
{
    *dname = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_X509_DISTINGUISHED_NAME,
                                   dname);
}


/*
 * Returns: 0 if not present, 1 if present, -1 on error
 */
int virIdentityGetSELinuxContext(virIdentity *ident,
                                 const char **context)
{
    *context = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_SELINUX_CONTEXT,
                                   context);
}


int virIdentityGetSystemToken(virIdentity *ident,
                              const char **token)
{
    *token = NULL;
    return virTypedParamsGetString(ident->params,
                                   ident->nparams,
                                   VIR_CONNECT_IDENTITY_SYSTEM_TOKEN,
                                   token);
}


int virIdentitySetUserName(virIdentity *ident,
                           const char *username)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_USER_NAME)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_USER_NAME,
                                   username);
}


int virIdentitySetUNIXUserID(virIdentity *ident,
                             uid_t uid)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_UNIX_USER_ID)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddULLong(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_UNIX_USER_ID,
                                   uid);
}


int virIdentitySetGroupName(virIdentity *ident,
                            const char *groupname)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_GROUP_NAME)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_GROUP_NAME,
                                   groupname);
}


int virIdentitySetUNIXGroupID(virIdentity *ident,
                              gid_t gid)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_UNIX_GROUP_ID)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddULLong(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_UNIX_GROUP_ID,
                                   gid);
}


int virIdentitySetProcessID(virIdentity *ident,
                            pid_t pid)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_PROCESS_ID)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddLLong(&ident->params,
                                  &ident->nparams,
                                  &ident->maxparams,
                                  VIR_CONNECT_IDENTITY_PROCESS_ID,
                                  pid);
}


int virIdentitySetProcessTime(virIdentity *ident,
                              unsigned long long timestamp)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_PROCESS_TIME)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddULLong(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_PROCESS_TIME,
                                   timestamp);
}



int virIdentitySetSASLUserName(virIdentity *ident,
                               const char *username)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_SASL_USER_NAME)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_SASL_USER_NAME,
                                   username);
}


int virIdentitySetX509DName(virIdentity *ident,
                            const char *dname)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_X509_DISTINGUISHED_NAME)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_X509_DISTINGUISHED_NAME,
                                   dname);
}


int virIdentitySetSELinuxContext(virIdentity *ident,
                                 const char *context)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_SELINUX_CONTEXT)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_SELINUX_CONTEXT,
                                   context);
}


int virIdentitySetSystemToken(virIdentity *ident,
                              const char *token)
{
    if (virTypedParamsGet(ident->params,
                          ident->nparams,
                          VIR_CONNECT_IDENTITY_SYSTEM_TOKEN)) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("Identity attribute is already set"));
        return -1;
    }

    return virTypedParamsAddString(&ident->params,
                                   &ident->nparams,
                                   &ident->maxparams,
                                   VIR_CONNECT_IDENTITY_SYSTEM_TOKEN,
                                   token);
}


int virIdentitySetParameters(virIdentity *ident,
                             virTypedParameterPtr params,
                             int nparams)
{
    if (virTypedParamsValidate(params, nparams,
                               VIR_CONNECT_IDENTITY_USER_NAME,
                               VIR_TYPED_PARAM_STRING,
                               VIR_CONNECT_IDENTITY_UNIX_USER_ID,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_CONNECT_IDENTITY_GROUP_NAME,
                               VIR_TYPED_PARAM_STRING,
                               VIR_CONNECT_IDENTITY_UNIX_GROUP_ID,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_CONNECT_IDENTITY_PROCESS_ID,
                               VIR_TYPED_PARAM_LLONG,
                               VIR_CONNECT_IDENTITY_PROCESS_TIME,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_CONNECT_IDENTITY_SASL_USER_NAME,
                               VIR_TYPED_PARAM_STRING,
                               VIR_CONNECT_IDENTITY_X509_DISTINGUISHED_NAME,
                               VIR_TYPED_PARAM_STRING,
                               VIR_CONNECT_IDENTITY_SELINUX_CONTEXT,
                               VIR_TYPED_PARAM_STRING,
                               VIR_CONNECT_IDENTITY_SYSTEM_TOKEN,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    virTypedParamsFree(ident->params, ident->nparams);
    ident->params = NULL;
    ident->nparams = 0;
    ident->maxparams = 0;

    virTypedParamsCopy(&ident->params, params, nparams);
    ident->nparams = nparams;
    ident->maxparams = nparams;

    return 0;
}


virTypedParamList *virIdentityGetParameters(virIdentity *ident)
{
    virTypedParameter *tmp = NULL;

    virTypedParamsCopy(&tmp, ident->params, ident->nparams);

    return virTypedParamListFromParams(&tmp, ident->nparams);
}
