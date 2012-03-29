/*
 * virnetsaslcontext.c: SASL encryption/auth handling
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <config.h>

#include <fnmatch.h>

#include "virnetsaslcontext.h"
#include "virnetmessage.h"

#include "virterror_internal.h"
#include "memory.h"
#include "threads.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


struct _virNetSASLContext {
    virMutex lock;
    const char *const*usernameWhitelist;
    int refs;
};

struct _virNetSASLSession {
    virMutex lock;
    sasl_conn_t *conn;
    int refs;
    size_t maxbufsize;
};


virNetSASLContextPtr virNetSASLContextNewClient(void)
{
    virNetSASLContextPtr ctxt;
    int err;

    err = sasl_client_init(NULL);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("failed to initialize SASL library: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return NULL;
    }

    if (VIR_ALLOC(ctxt) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&ctxt->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(ctxt);
        return NULL;
    }

    ctxt->refs = 1;

    return ctxt;
}

virNetSASLContextPtr virNetSASLContextNewServer(const char *const*usernameWhitelist)
{
    virNetSASLContextPtr ctxt;
    int err;

    err = sasl_server_init(NULL, "libvirt");
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("failed to initialize SASL library: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return NULL;
    }

    if (VIR_ALLOC(ctxt) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&ctxt->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(ctxt);
        return NULL;
    }

    ctxt->usernameWhitelist = usernameWhitelist;
    ctxt->refs = 1;

    return ctxt;
}

int virNetSASLContextCheckIdentity(virNetSASLContextPtr ctxt,
                                   const char *identity)
{
    const char *const*wildcards;
    int ret = -1;

    virMutexLock(&ctxt->lock);

    /* If the list is not set, allow any DN. */
    wildcards = ctxt->usernameWhitelist;
    if (!wildcards) {
        ret = 1; /* No ACL, allow all */
        goto cleanup;
    }

    while (*wildcards) {
        int rv = fnmatch (*wildcards, identity, 0);
        if (rv == 0) {
            ret = 1;
            goto cleanup; /* Succesful match */
        }
        if (rv != FNM_NOMATCH) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Malformed TLS whitelist regular expression '%s'"),
                        *wildcards);
            goto cleanup;
        }

        wildcards++;
    }

    /* Denied */
    VIR_ERROR(_("SASL client %s not allowed in whitelist"), identity);

    /* This is the most common error: make it informative. */
    virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                _("Client's username is not on the list of allowed clients"));
    ret = 0;

cleanup:
    virMutexUnlock(&ctxt->lock);
    return ret;
}


void virNetSASLContextRef(virNetSASLContextPtr ctxt)
{
    virMutexLock(&ctxt->lock);
    ctxt->refs++;
    virMutexUnlock(&ctxt->lock);
}

void virNetSASLContextFree(virNetSASLContextPtr ctxt)
{
    if (!ctxt)
        return;

    virMutexLock(&ctxt->lock);
    ctxt->refs--;
    if (ctxt->refs > 0) {
        virMutexUnlock(&ctxt->lock);
        return;
    }

    virMutexUnlock(&ctxt->lock);
    virMutexDestroy(&ctxt->lock);
    VIR_FREE(ctxt);
}

virNetSASLSessionPtr virNetSASLSessionNewClient(virNetSASLContextPtr ctxt ATTRIBUTE_UNUSED,
                                                const char *service,
                                                const char *hostname,
                                                const char *localAddr,
                                                const char *remoteAddr,
                                                const sasl_callback_t *cbs)
{
    virNetSASLSessionPtr sasl = NULL;
    int err;

    if (VIR_ALLOC(sasl) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virMutexInit(&sasl->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(sasl);
        return NULL;
    }

    sasl->refs = 1;
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to create SASL client context: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    return sasl;

cleanup:
    virNetSASLSessionFree(sasl);
    return NULL;
}

virNetSASLSessionPtr virNetSASLSessionNewServer(virNetSASLContextPtr ctxt ATTRIBUTE_UNUSED,
                                                const char *service,
                                                const char *localAddr,
                                                const char *remoteAddr)
{
    virNetSASLSessionPtr sasl = NULL;
    int err;

    if (VIR_ALLOC(sasl) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virMutexInit(&sasl->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(sasl);
        return NULL;
    }

    sasl->refs = 1;
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to create SASL client context: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    return sasl;

cleanup:
    virNetSASLSessionFree(sasl);
    return NULL;
}

void virNetSASLSessionRef(virNetSASLSessionPtr sasl)
{
    virMutexLock(&sasl->lock);
    sasl->refs++;
    virMutexUnlock(&sasl->lock);
}

int virNetSASLSessionExtKeySize(virNetSASLSessionPtr sasl,
                                int ssf)
{
    int err;
    int ret = -1;
    virMutexLock(&sasl->lock);

    err = sasl_setprop(sasl->conn, SASL_SSF_EXTERNAL, &ssf);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot set external SSF %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    ret = 0;

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}

const char *virNetSASLSessionGetIdentity(virNetSASLSessionPtr sasl)
{
    const void *val = NULL;
    int err;
    virMutexLock(&sasl->lock);

    err = sasl_getprop(sasl->conn, SASL_USERNAME, &val);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("cannot query SASL username on connection %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        val = NULL;
        goto cleanup;
    }
    if (val == NULL) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("no client username was found"));
        goto cleanup;
    }
    VIR_DEBUG("SASL client username %s", (const char *)val);

cleanup:
    virMutexUnlock(&sasl->lock);
    return (const char*)val;
}


int virNetSASLSessionGetKeySize(virNetSASLSessionPtr sasl)
{
    int err;
    int ssf;
    const void *val;

    virMutexLock(&sasl->lock);
    err = sasl_getprop(sasl->conn, SASL_SSF, &val);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("cannot query SASL ssf on connection %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        ssf = -1;
        goto cleanup;
    }
    ssf = *(const int *)val;

cleanup:
    virMutexUnlock(&sasl->lock);
    return ssf;
}

int virNetSASLSessionSecProps(virNetSASLSessionPtr sasl,
                              int minSSF,
                              int maxSSF,
                              bool allowAnonymous)
{
    sasl_security_properties_t secprops;
    int err;
    int ret = -1;

    VIR_DEBUG("minSSF=%d maxSSF=%d allowAnonymous=%d maxbufsize=%zu",
              minSSF, maxSSF, allowAnonymous, sasl->maxbufsize);

    virMutexLock(&sasl->lock);
    memset(&secprops, 0, sizeof(secprops));

    secprops.min_ssf = minSSF;
    secprops.max_ssf = maxSSF;
    secprops.maxbufsize = sasl->maxbufsize;
    secprops.security_flags = allowAnonymous ? 0 :
        SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;

    err = sasl_setprop(sasl->conn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot set security props %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    ret = 0;

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}


static int virNetSASLSessionUpdateBufSize(virNetSASLSessionPtr sasl)
{
    union {
        unsigned *maxbufsize;
        const void *ptr;
    } u;
    int err;

    err = sasl_getprop(sasl->conn, SASL_MAXOUTBUF, &u.ptr);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot get security props %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return -1;
    }

    VIR_DEBUG("Negotiated bufsize is %u vs requested size %zu",
              *u.maxbufsize, sasl->maxbufsize);
    sasl->maxbufsize = *u.maxbufsize;
    return 0;
}

char *virNetSASLSessionListMechanisms(virNetSASLSessionPtr sasl)
{
    const char *mechlist;
    char *ret = NULL;
    int err;

    virMutexLock(&sasl->lock);
    err = sasl_listmech(sasl->conn,
                        NULL, /* Don't need to set user */
                        "", /* Prefix */
                        ",", /* Separator */
                        "", /* Suffix */
                        &mechlist,
                        NULL,
                        NULL);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot list SASL mechanisms %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        goto cleanup;
    }
    if (!(ret = strdup(mechlist))) {
        virReportOOMError();
        goto cleanup;
    }

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}


int virNetSASLSessionClientStart(virNetSASLSessionPtr sasl,
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

    virMutexLock(&sasl->lock);
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        break;
    }

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}


int virNetSASLSessionClientStep(virNetSASLSessionPtr sasl,
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

    VIR_DEBUG("sasl=%p serverin=%s serverinlen=%zu prompt_need=%p clientout=%p clientoutlen=%p",
              sasl, serverin, serverinlen, prompt_need, clientout, clientoutlen);

    virMutexLock(&sasl->lock);
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to step SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        break;
    }

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}

int virNetSASLSessionServerStart(virNetSASLSessionPtr sasl,
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

    virMutexLock(&sasl->lock);
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        break;
    }

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}


int virNetSASLSessionServerStep(virNetSASLSessionPtr sasl,
                                const char *clientin,
                                size_t clientinlen,
                                const char **serverout,
                                size_t *serveroutlen)
{
    unsigned inlen = clientinlen;
    unsigned outlen = 0;
    int err;
    int ret = -1;

    virMutexLock(&sasl->lock);
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
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        break;
    }

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}

size_t virNetSASLSessionGetMaxBufSize(virNetSASLSessionPtr sasl)
{
    size_t ret;
    virMutexLock(&sasl->lock);
    ret = sasl->maxbufsize;
    virMutexUnlock(&sasl->lock);
    return ret;
}

ssize_t virNetSASLSessionEncode(virNetSASLSessionPtr sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen)
{
    unsigned inlen = inputLen;
    unsigned outlen = 0;
    int err;
    ssize_t ret = -1;

    virMutexLock(&sasl->lock);
    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %zu too long, max %zu"),
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
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("failed to encode SASL data: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }
    ret = 0;

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}

ssize_t virNetSASLSessionDecode(virNetSASLSessionPtr sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen)
{
    unsigned inlen = inputLen;
    unsigned outlen = 0;
    int err;
    ssize_t ret = -1;

    virMutexLock(&sasl->lock);
    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %zu too long, max %zu"),
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
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("failed to decode SASL data: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }
    ret = 0;

cleanup:
    virMutexUnlock(&sasl->lock);
    return ret;
}

void virNetSASLSessionFree(virNetSASLSessionPtr sasl)
{
    if (!sasl)
        return;

    virMutexLock(&sasl->lock);
    sasl->refs--;
    if (sasl->refs > 0) {
        virMutexUnlock(&sasl->lock);
        return;
    }

    if (sasl->conn)
        sasl_dispose(&sasl->conn);

    virMutexUnlock(&sasl->lock);
    virMutexDestroy(&sasl->lock);
    VIR_FREE(sasl);
}
