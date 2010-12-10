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
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


struct _virNetSASLContext {
    const char *const*usernameWhitelist;
    int refs;
};

struct _virNetSASLSession {
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

    ctxt->usernameWhitelist = usernameWhitelist;
    ctxt->refs = 1;

    return ctxt;
}

int virNetSASLContextCheckIdentity(virNetSASLContextPtr ctxt,
                                   const char *identity)
{
    const char *const*wildcards;

    /* If the list is not set, allow any DN. */
    wildcards = ctxt->usernameWhitelist;
    if (!wildcards)
        return 1; /* No ACL, allow all */

    while (*wildcards) {
        int ret = fnmatch (*wildcards, identity, 0);
        if (ret == 0) /* Succesful match */
            return 1;
        if (ret != FNM_NOMATCH) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Malformed TLS whitelist regular expression '%s'"),
                        *wildcards);
            return -1;
        }

        wildcards++;
    }

    /* Denied */
    VIR_ERROR(_("SASL client %s not allowed in whitelist"), identity);

    /* This is the most common error: make it informative. */
    virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                _("Client's username is not on the list of allowed clients"));
    return 0;
}


void virNetSASLContextRef(virNetSASLContextPtr ctxt)
{
    ctxt->refs++;
}

void virNetSASLContextFree(virNetSASLContextPtr ctxt)
{
    if (!ctxt)
        return;

    ctxt->refs--;
    if (ctxt->refs > 0)
        return;

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
    sasl->refs++;
}

int virNetSASLSessionExtKeySize(virNetSASLSessionPtr sasl,
                                int ssf)
{
    int err;

    err = sasl_setprop(sasl->conn, SASL_SSF_EXTERNAL, &ssf);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot set external SSF %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return -1;
    }
    return 0;
}

const char *virNetSASLSessionGetIdentity(virNetSASLSessionPtr sasl)
{
    const void *val;
    int err;

    err = sasl_getprop(sasl->conn, SASL_USERNAME, &val);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("cannot query SASL username on connection %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return NULL;
    }
    if (val == NULL) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("no client username was found"));
        return NULL;
    }
    VIR_DEBUG("SASL client username %s", (const char *)val);

    return (const char*)val;
}


int virNetSASLSessionGetKeySize(virNetSASLSessionPtr sasl)
{
    int err;
    int ssf;
    const void *val;
    err = sasl_getprop(sasl->conn, SASL_SSF, &val);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("cannot query SASL ssf on connection %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return -1;
    }
    ssf = *(const int *)val;
    return ssf;
}

int virNetSASLSessionSecProps(virNetSASLSessionPtr sasl,
                              int minSSF,
                              int maxSSF,
                              bool allowAnonymous)
{
    sasl_security_properties_t secprops;
    int err;

    VIR_DEBUG("minSSF=%d maxSSF=%d allowAnonymous=%d maxbufsize=%zu",
              minSSF, maxSSF, allowAnonymous, sasl->maxbufsize);

    memset(&secprops, 0, sizeof secprops);

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
        return -1;
    }

    return 0;
}


static int virNetSASLSessionUpdateBufSize(virNetSASLSessionPtr sasl)
{
    unsigned *maxbufsize;
    int err;

    err = sasl_getprop(sasl->conn, SASL_MAXOUTBUF, (const void **)&maxbufsize);
    if (err != SASL_OK) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot get security props %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        return -1;
    }

    VIR_DEBUG("Negotiated bufsize is %u vs requested size %zu",
              *maxbufsize, sasl->maxbufsize);
    sasl->maxbufsize = *maxbufsize;
    return 0;
}

char *virNetSASLSessionListMechanisms(virNetSASLSessionPtr sasl)
{
    const char *mechlist;
    char *ret;
    int err;

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
        return NULL;
    }
    if (!(ret = strdup(mechlist))) {
        virReportOOMError();
        return NULL;
    }
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

    VIR_DEBUG("sasl=%p mechlist=%s prompt_need=%p clientout=%p clientoutlen=%p mech=%p",
              sasl, mechlist, prompt_need, clientout, clientoutlen, mech);

    int err = sasl_client_start(sasl->conn,
                                mechlist,
                                prompt_need,
                                clientout,
                                &outlen,
                                mech);

    *clientoutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            return -1;
        return VIR_NET_SASL_COMPLETE;
    case SASL_CONTINUE:
        return VIR_NET_SASL_CONTINUE;
    case SASL_INTERACT:
        return VIR_NET_SASL_INTERACT;

    default:
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        return -1;
    }
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

    VIR_DEBUG("sasl=%p serverin=%s serverinlen=%zu prompt_need=%p clientout=%p clientoutlen=%p",
              sasl, serverin, serverinlen, prompt_need, clientout, clientoutlen);

    int err = sasl_client_step(sasl->conn,
                               serverin,
                               inlen,
                               prompt_need,
                               clientout,
                               &outlen);
    *clientoutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            return -1;
        return VIR_NET_SASL_COMPLETE;
    case SASL_CONTINUE:
        return VIR_NET_SASL_CONTINUE;
    case SASL_INTERACT:
        return VIR_NET_SASL_INTERACT;

    default:
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to step SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        return -1;
    }
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
    int err = sasl_server_start(sasl->conn,
                                mechname,
                                clientin,
                                inlen,
                                serverout,
                                &outlen);

    *serveroutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            return -1;
        return VIR_NET_SASL_COMPLETE;
    case SASL_CONTINUE:
        return VIR_NET_SASL_CONTINUE;
    case SASL_INTERACT:
        return VIR_NET_SASL_INTERACT;

    default:
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        return -1;
    }
}


int virNetSASLSessionServerStep(virNetSASLSessionPtr sasl,
                                const char *clientin,
                                size_t clientinlen,
                                const char **serverout,
                                size_t *serveroutlen)
{
    unsigned inlen = clientinlen;
    unsigned outlen = 0;

    int err = sasl_server_step(sasl->conn,
                               clientin,
                               inlen,
                               serverout,
                               &outlen);

    *serveroutlen = outlen;

    switch (err) {
    case SASL_OK:
        if (virNetSASLSessionUpdateBufSize(sasl) < 0)
            return -1;
        return VIR_NET_SASL_COMPLETE;
    case SASL_CONTINUE:
        return VIR_NET_SASL_CONTINUE;
    case SASL_INTERACT:
        return VIR_NET_SASL_INTERACT;

    default:
        virNetError(VIR_ERR_AUTH_FAILED,
                    _("Failed to start SASL negotiation: %d (%s)"),
                    err, sasl_errdetail(sasl->conn));
        return -1;
    }
}

size_t virNetSASLSessionGetMaxBufSize(virNetSASLSessionPtr sasl)
{
    return sasl->maxbufsize;
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

    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %zu too long, max %zu"),
                             inputLen, sasl->maxbufsize);
        return -1;
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
        return -1;
    }
    return 0;
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

    if (inputLen > sasl->maxbufsize) {
        virReportSystemError(EINVAL,
                             _("SASL data length %zu too long, max %zu"),
                             inputLen, sasl->maxbufsize);
        return -1;
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
        return -1;
    }
    return 0;
}

void virNetSASLSessionFree(virNetSASLSessionPtr sasl)
{
    if (!sasl)
        return;

    sasl->refs--;
    if (sasl->refs > 0)
        return;

    if (sasl->conn)
        sasl_dispose(&sasl->conn);

    VIR_FREE(sasl);
}
