/*
 * virnetsaslcontext.c: SASL encryption/auth handling
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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

#include "virnetsaslcontext.h"

#include "virerror.h"
#include "virthread.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netsaslcontext");

struct _virNetSASLContext {
    virObjectLockable parent;

    const char *const *usernameACL;
    unsigned int tcpMinSSF;
};

struct _virNetSASLSession {
    virObjectLockable parent;

    sasl_conn_t *conn;
    size_t maxbufsize;
    sasl_callback_t *callbacks;
};


static virClass *virNetSASLContextClass;
static virClass *virNetSASLSessionClass;
static void virNetSASLContextDispose(void *obj);
static void virNetSASLSessionDispose(void *obj);

static int virNetSASLContextOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetSASLContext, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virNetSASLSession, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetSASLContext);

/* Apple have annotated all SASL functions as deprecated for
 * unknown reasons. Since they still work, lets just ignore
 * the warnings. If Apple finally delete the SASL functions
 * our configure check should already catch that
 */
#ifdef __APPLE__
VIR_WARNINGS_NO_DEPRECATED
#endif

static int virNetSASLContextClientOnceInit(void)
{
    int err = sasl_client_init(NULL);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("failed to initialize SASL library: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        return -1;
    }

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetSASLContextClient);


static int virNetSASLContextServerOnceInit(void)
{
    int err = sasl_server_init(NULL, "libvirt");
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("failed to initialize SASL library: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        return -1;
    }

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetSASLContextServer);


virNetSASLContext *virNetSASLContextNewClient(void)
{
    virNetSASLContext *ctxt;

    if (virNetSASLContextInitialize() < 0 ||
        virNetSASLContextClientInitialize() < 0)
        return NULL;

    if (!(ctxt = virObjectLockableNew(virNetSASLContextClass)))
        return NULL;

    return ctxt;
}

virNetSASLContext *virNetSASLContextNewServer(const char *const *usernameACL,
                                              unsigned int tcpMinSSF)
{
    virNetSASLContext *ctxt;

    if (virNetSASLContextInitialize() < 0 ||
        virNetSASLContextServerInitialize() < 0)
        return NULL;

    if (!(ctxt = virObjectLockableNew(virNetSASLContextClass)))
        return NULL;

    ctxt->usernameACL = usernameACL;
    ctxt->tcpMinSSF = tcpMinSSF;

    return ctxt;
}

int virNetSASLContextCheckIdentity(virNetSASLContext *ctxt,
                                   const char *identity)
{
    const char *const*wildcards;
    int ret = -1;

    virObjectLock(ctxt);

    /* If the list is not set, allow any DN. */
    wildcards = ctxt->usernameACL;
    if (!wildcards) {
        ret = 1; /* No ACL, allow all */
        goto cleanup;
    }

    while (*wildcards) {
        if (g_pattern_match_simple(*wildcards, identity)) {
            ret = 1;
            goto cleanup; /* Successful match */
        }

        wildcards++;
    }

    /* Denied */
    VIR_ERROR(_("SASL client identity '%1$s' not allowed by ACL"), identity);

    /* This is the most common error: make it informative. */
    virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                   _("Client's username is not on the list of allowed clients"));
    ret = 0;

 cleanup:
    virObjectUnlock(ctxt);
    return ret;
}


unsigned int virNetSASLContextGetTCPMinSSF(virNetSASLContext *ctxt)
{
    return ctxt->tcpMinSSF;
}


virNetSASLSession *virNetSASLSessionNewClient(virNetSASLContext *ctxt G_GNUC_UNUSED,
                                                const char *service,
                                                const char *hostname,
                                                const char *localAddr,
                                                const char *remoteAddr,
                                                sasl_callback_t *cbs)
{
    virNetSASLSession *sasl = NULL;
    int err;

    if (!(sasl = virObjectLockableNew(virNetSASLSessionClass)))
        return NULL;

    /* Arbitrary size for amount of data we can encode in a single block */
    sasl->maxbufsize = 1 << 16;

    err = sasl_client_new(service,
                          hostname,
                          localAddr,
                          remoteAddr,
                          cbs,
                          SASL_SUCCESS_DATA,
                          &sasl->conn);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to create SASL client context: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }
    sasl->callbacks = cbs;

    return sasl;

 cleanup:
    virObjectUnref(sasl);
    return NULL;
}

virNetSASLSession *virNetSASLSessionNewServer(virNetSASLContext *ctxt G_GNUC_UNUSED,
                                                const char *service,
                                                const char *localAddr,
                                                const char *remoteAddr)
{
    virNetSASLSession *sasl = NULL;
    int err;

    if (!(sasl = virObjectLockableNew(virNetSASLSessionClass)))
        return NULL;

    /* Arbitrary size for amount of data we can encode in a single block */
    sasl->maxbufsize = 1 << 16;

    err = sasl_server_new(service,
                          NULL,
                          NULL,
                          localAddr,
                          remoteAddr,
                          NULL,
                          SASL_SUCCESS_DATA,
                          &sasl->conn);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to create SASL client context: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    return sasl;

 cleanup:
    virObjectUnref(sasl);
    return NULL;
}

int virNetSASLSessionExtKeySize(virNetSASLSession *sasl,
                                int ssf)
{
    int err;
    int ret = -1;
    virObjectLock(sasl);

    err = sasl_setprop(sasl->conn, SASL_SSF_EXTERNAL, &ssf);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set external SSF %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}

const char *virNetSASLSessionGetIdentity(virNetSASLSession *sasl)
{
    const void *val = NULL;
    int err;
    virObjectLock(sasl);

    err = sasl_getprop(sasl->conn, SASL_USERNAME, &val);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("cannot query SASL username on connection %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        val = NULL;
        goto cleanup;
    }
    if (val == NULL) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("no client username was found"));
        goto cleanup;
    }
    VIR_DEBUG("SASL client username %s", (const char *)val);

 cleanup:
    virObjectUnlock(sasl);
    return (const char*)val;
}


int virNetSASLSessionGetKeySize(virNetSASLSession *sasl)
{
    int err;
    int ssf;
    const void *val;

    virObjectLock(sasl);
    err = sasl_getprop(sasl->conn, SASL_SSF, &val);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("cannot query SASL ssf on connection %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        ssf = -1;
        goto cleanup;
    }
    ssf = *(const int *)val;

 cleanup:
    virObjectUnlock(sasl);
    return ssf;
}

int virNetSASLSessionSecProps(virNetSASLSession *sasl,
                              int minSSF,
                              int maxSSF,
                              bool allowAnonymous)
{
    sasl_security_properties_t secprops = { 0 };
    int err;
    int ret = -1;

    VIR_DEBUG("minSSF=%d maxSSF=%d allowAnonymous=%d maxbufsize=%zu",
              minSSF, maxSSF, allowAnonymous, sasl->maxbufsize);

    virObjectLock(sasl);

    secprops.min_ssf = minSSF;
    secprops.max_ssf = maxSSF;
    secprops.maxbufsize = sasl->maxbufsize;
    secprops.security_flags = allowAnonymous ? 0 :
        SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;

    err = sasl_setprop(sasl->conn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set security props %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}


static int virNetSASLSessionUpdateBufSize(virNetSASLSession *sasl)
{
    union {
        unsigned *maxbufsize;
        const void *ptr;
    } u;
    int err;

    err = sasl_getprop(sasl->conn, SASL_MAXOUTBUF, &u.ptr);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot get security props %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        return -1;
    }

    VIR_DEBUG("Negotiated bufsize is %u vs requested size %zu",
              *u.maxbufsize, sasl->maxbufsize);
    sasl->maxbufsize = *u.maxbufsize;
    return 0;
}

char *virNetSASLSessionListMechanisms(virNetSASLSession *sasl)
{
    const char *mechlist;
    char *ret = NULL;
    int err;

    virObjectLock(sasl);
    err = sasl_listmech(sasl->conn,
                        NULL, /* Don't need to set user */
                        "", /* Prefix */
                        ",", /* Separator */
                        "", /* Suffix */
                        &mechlist,
                        NULL,
                        NULL);
    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot list SASL mechanisms %1$d (%2$s)"),
                       err, sasl_errdetail(sasl->conn));
        goto cleanup;
    }
    VIR_DEBUG("SASL mechanism list is '%s'", mechlist);
    if (STREQ(mechlist, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no SASL mechanisms are available"));
        goto cleanup;
    }
    ret = g_strdup(mechlist);

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}


int virNetSASLSessionClientStart(virNetSASLSession *sasl,
                                 const char *mechlist,
                                 sasl_interact_t **prompt_need,
                                 const char **clientout,
                                 size_t *clientoutlen,
                                 const char **mech)
{
    unsigned outlen = 0;
    int err;
    int ret = -1;

    VIR_DEBUG("sasl=%p mechlist=%s prompt_need=%p clientout=%p clientoutlen=%p mech=%p",
              sasl, mechlist, prompt_need, clientout, clientoutlen, mech);

    virObjectLock(sasl);
    err = sasl_client_start(sasl->conn,
                            mechlist,
                            prompt_need,
                            clientout,
                            &outlen,
                            mech);

    *clientoutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            goto cleanup;
        ret = VIR_NET_SASL_COMPLETE;
        break;
    case SASL_CONTINUE:
        ret = VIR_NET_SASL_CONTINUE;
        break;
    case SASL_INTERACT:
        ret = VIR_NET_SASL_INTERACT;
        break;
    default:
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to start SASL negotiation: %1$d (%2$s)"),
                       err, sasl_errdetail(sasl->conn));
        break;
    }

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}


int virNetSASLSessionClientStep(virNetSASLSession *sasl,
                                const char *serverin,
                                size_t serverinlen,
                                sasl_interact_t **prompt_need,
                                const char **clientout,
                                size_t *clientoutlen)
{
    unsigned inlen = serverinlen;
    unsigned outlen = 0;
    int err;
    int ret = -1;

    VIR_DEBUG("sasl=%p serverin=%p serverinlen=%zu prompt_need=%p clientout=%p clientoutlen=%p",
              sasl, serverin, serverinlen, prompt_need, clientout, clientoutlen);

    virObjectLock(sasl);
    err = sasl_client_step(sasl->conn,
                           serverin,
                           inlen,
                           prompt_need,
                           clientout,
                           &outlen);
    *clientoutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            goto cleanup;
        ret = VIR_NET_SASL_COMPLETE;
        break;
    case SASL_CONTINUE:
        ret = VIR_NET_SASL_CONTINUE;
        break;
    case SASL_INTERACT:
        ret = VIR_NET_SASL_INTERACT;
        break;
    default:
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to step SASL negotiation: %1$d (%2$s)"),
                       err, sasl_errdetail(sasl->conn));
        break;
    }

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}

int virNetSASLSessionServerStart(virNetSASLSession *sasl,
                                 const char *mechname,
                                 const char *clientin,
                                 size_t clientinlen,
                                 const char **serverout,
                                 size_t *serveroutlen)
{
    unsigned inlen = clientinlen;
    unsigned outlen = 0;
    int err;
    int ret = -1;

    virObjectLock(sasl);
    err = sasl_server_start(sasl->conn,
                            mechname,
                            clientin,
                            inlen,
                            serverout,
                            &outlen);

    *serveroutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            goto cleanup;
        ret = VIR_NET_SASL_COMPLETE;
        break;
    case SASL_CONTINUE:
        ret = VIR_NET_SASL_CONTINUE;
        break;
    case SASL_INTERACT:
        ret = VIR_NET_SASL_INTERACT;
        break;
    default:
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to start SASL negotiation: %1$d (%2$s)"),
                       err, sasl_errdetail(sasl->conn));
        break;
    }

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}


int virNetSASLSessionServerStep(virNetSASLSession *sasl,
                                const char *clientin,
                                size_t clientinlen,
                                const char **serverout,
                                size_t *serveroutlen)
{
    unsigned inlen = clientinlen;
    unsigned outlen = 0;
    int err;
    int ret = -1;

    virObjectLock(sasl);
    err = sasl_server_step(sasl->conn,
                           clientin,
                           inlen,
                           serverout,
                           &outlen);

    *serveroutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            goto cleanup;
        ret = VIR_NET_SASL_COMPLETE;
        break;
    case SASL_CONTINUE:
        ret = VIR_NET_SASL_CONTINUE;
        break;
    case SASL_INTERACT:
        ret = VIR_NET_SASL_INTERACT;
        break;
    default:
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("Failed to start SASL negotiation: %1$d (%2$s)"),
                       err, sasl_errdetail(sasl->conn));
        break;
    }

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}

size_t virNetSASLSessionGetMaxBufSize(virNetSASLSession *sasl)
{
    size_t ret;
    virObjectLock(sasl);
    ret = sasl->maxbufsize;
    virObjectUnlock(sasl);
    return ret;
}

ssize_t virNetSASLSessionEncode(virNetSASLSession *sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen)
{
    unsigned inlen = inputLen;
    unsigned outlen = 0;
    int err;
    ssize_t ret = -1;

    virObjectLock(sasl);
    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %1$zu too long, max %2$zu"),
                             inputLen, sasl->maxbufsize);
        goto cleanup;
    }

    err = sasl_encode(sasl->conn,
                      input,
                      inlen,
                      output,
                      &outlen);
    *outputlen = outlen;

    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to encode SASL data: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }
    ret = 0;

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}

ssize_t virNetSASLSessionDecode(virNetSASLSession *sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen)
{
    unsigned inlen = inputLen;
    unsigned outlen = 0;
    int err;
    ssize_t ret = -1;

    virObjectLock(sasl);
    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %1$zu too long, max %2$zu"),
                             inputLen, sasl->maxbufsize);
        goto cleanup;
    }

    err = sasl_decode(sasl->conn,
                      input,
                      inlen,
                      output,
                      &outlen);
    *outputlen = outlen;
    if (err != SASL_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to decode SASL data: %1$d (%2$s)"),
                       err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }
    ret = 0;

 cleanup:
    virObjectUnlock(sasl);
    return ret;
}

void virNetSASLContextDispose(void *obj G_GNUC_UNUSED)
{
    return;
}

void virNetSASLSessionDispose(void *obj)
{
    virNetSASLSession *sasl = obj;

    if (sasl->conn)
        sasl_dispose(&sasl->conn);
    g_free(sasl->callbacks);
}

#ifdef __APPLE__
VIR_WARNINGS_RESET
#endif
