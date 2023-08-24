/*
 * libxl_migration.c: methods for handling migration with libxenlight
 *
 * Copyright (C) 2014-2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virstring.h"
#include "virobject.h"
#include "virthread.h"
#include "virhook.h"
#include "rpc/virnetsocket.h"
#include "libxl_api_wrapper.h"
#include "libxl_domain.h"
#include "libxl_conf.h"
#include "libxl_migration.h"
#include "locking/domain_lock.h"
#include "virtypedparam.h"
#include "virfdstream.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_migration");

typedef struct _libxlMigrationCookie libxlMigrationCookie;
struct _libxlMigrationCookie {
    /* Host properties */
    char *srcHostname;
    uint32_t xenMigStreamVer;

    /* Guest properties */
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;
};

typedef struct _libxlMigrationDstArgs {
    virObject parent;

    int recvfd;
    virConnectPtr conn;
    virDomainObj *vm;
    unsigned int flags;
    libxlMigrationCookie *migcookie;

    /* for freeing listen sockets */
    virNetSocket **socks;
    size_t nsocks;
} libxlMigrationDstArgs;

static virClass *libxlMigrationDstArgsClass;


static void
libxlMigrationCookieFree(libxlMigrationCookie *mig)
{
    if (!mig)
        return;

    g_free(mig->srcHostname);
    g_free(mig->name);
    g_free(mig);
}

static libxlMigrationCookie *
libxlMigrationCookieNew(virDomainObj *dom)
{
    libxlMigrationCookie *mig = NULL;

    mig = g_new0(libxlMigrationCookie, 1);

    mig->name = g_strdup(dom->def->name);

    memcpy(mig->uuid, dom->def->uuid, VIR_UUID_BUFLEN);

    if (!(mig->srcHostname = virGetHostname()))
        goto error;

    mig->xenMigStreamVer = LIBXL_SAVE_VERSION;

    return mig;

 error:
    libxlMigrationCookieFree(mig);
    return NULL;
}


static int
libxlMigrationBakeCookie(libxlMigrationCookie *mig,
                         char **cookieout,
                         int *cookieoutlen)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!cookieout || !cookieoutlen)
        return 0;

    *cookieoutlen = 0;
    virUUIDFormat(mig->uuid, uuidstr);

    virBufferAddLit(&buf, "<libxl-migration>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", mig->name);
    virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", uuidstr);
    virBufferEscapeString(&buf, "<hostname>%s</hostname>\n", mig->srcHostname);
    virBufferAsprintf(&buf, "<migration-stream-version>%u</migration-stream-version>\n", mig->xenMigStreamVer);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</libxl-migration>\n");

    *cookieout = virBufferContentAndReset(&buf);
    *cookieoutlen = strlen(*cookieout) + 1;

    VIR_DEBUG("cookielen=%d cookie=%s", *cookieoutlen, *cookieout);

    return 0;
}

static int
libxlMigrationEatCookie(const char *cookiein,
                        int cookieinlen,
                        libxlMigrationCookie **migout)
{
    libxlMigrationCookie *mig = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *uuidstr = NULL;

    /*
     * Assume a legacy (V1) migration stream if request came from a
     * source host without cookie support, and hence no way to
     * specify a stream version.
     */
    if (!cookiein || !cookieinlen) {
        mig = g_new0(libxlMigrationCookie, 1);

        mig->xenMigStreamVer = 1;
        *migout = mig;
        return 0;
    }

    if (cookiein[cookieinlen-1] != '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration cookie was not NULL terminated"));
        return -1;
    }

    VIR_DEBUG("cookielen=%d cookie='%s'", cookieinlen, NULLSTR(cookiein));

    mig = g_new0(libxlMigrationCookie, 1);

    if (!(doc = virXMLParseStringCtxt(cookiein,
                                      _("(libxl_migration_cookie)"),
                                      &ctxt)))
        goto error;

    /* Extract domain name */
    if (!(mig->name = virXPathString("string(./name[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing name element in migration data"));
        goto error;
    }

    /* Extract domain uuid */
    uuidstr = virXPathString("string(./uuid[1])", ctxt);
    if (!uuidstr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing uuid element in migration data"));
        goto error;
    }
    if (virUUIDParse(uuidstr, mig->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed uuid element"));
        goto error;
    }

    if (virXPathUInt("string(./migration-stream-version[1])",
                     ctxt, &mig->xenMigStreamVer) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing Xen migration stream version"));
        goto error;
    }

    *migout = mig;
    return 0;

 error:
    libxlMigrationCookieFree(mig);
    return -1;
}

static void
libxlMigrationDstArgsDispose(void *obj)
{
    libxlMigrationDstArgs *args = obj;

    libxlMigrationCookieFree(args->migcookie);
    g_free(args->socks);
    virObjectUnref(args->conn);
    virObjectUnref(args->vm);
}

static int
libxlMigrationDstArgsOnceInit(void)
{
    if (!VIR_CLASS_NEW(libxlMigrationDstArgs, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlMigrationDstArgs);

static void
libxlDoMigrateDstReceive(void *opaque)
{
    libxlMigrationDstArgs *args = opaque;
    virDomainObj *vm = args->vm;
    virNetSocket **socks = args->socks;
    size_t nsocks = args->nsocks;
    libxlDriverPrivate *driver = args->conn->privateData;
    int recvfd = args->recvfd;
    size_t i;

    virObjectRef(vm);

    /*
     * Always start the domain paused.  If needed, unpause in the
     * finish phase, after transfer of the domain is complete.
     * Errors and cleanup are also handled in the finish phase.
     */
    libxlDomainStartRestore(driver, vm, true, recvfd,
                            args->migcookie->xenMigStreamVer);

    /* Remove all listen socks from event handler, and close them. */
    for (i = 0; i < nsocks; i++) {
        virNetSocketRemoveIOCallback(socks[i]);
        virNetSocketClose(socks[i]);
        g_clear_pointer(&socks[i], virObjectUnref);
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);
    virDomainObjEndAPI(&vm);
}


static void
libxlMigrateDstReceive(virNetSocket *sock,
                       int events G_GNUC_UNUSED,
                       void *opaque)
{
    libxlMigrationDstArgs *args = opaque;
    virNetSocket **socks = args->socks;
    size_t nsocks = args->nsocks;
    libxlDomainObjPrivate *priv = args->vm->privateData;
    virNetSocket *client_sock;
    int recvfd = -1;
    size_t i;
    g_autofree char *name = NULL;

    /* Accept migration connection */
    if (virNetSocketAccept(sock, &client_sock) < 0 || !client_sock) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to accept migration connection"));
        goto fail;
    }
    VIR_DEBUG("Accepted migration connection."
              "  Spawning thread to process migration data");
    recvfd = virNetSocketDupFD(client_sock, true);
    virObjectUnref(client_sock);

    /*
     * Avoid blocking the event loop.  Start a thread to receive
     * the migration data
     */
    args->recvfd = recvfd;
    VIR_FREE(priv->migrationDstReceiveThr);
    priv->migrationDstReceiveThr = g_new0(virThread, 1);

    name = g_strdup_printf("mig-%s", args->vm->def->name);
    if (virThreadCreateFull(priv->migrationDstReceiveThr, true,
                            libxlDoMigrateDstReceive,
                            name,
                            false,
                            args) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to create thread for receiving migration data"));
        goto fail;
    }

    return;

 fail:
    /* Remove all listen socks from event handler, and close them. */
    for (i = 0; i < nsocks; i++) {
        virNetSocketUpdateIOCallback(socks[i], 0);
        virNetSocketRemoveIOCallback(socks[i]);
        g_clear_pointer(&socks[i], virNetSocketClose);
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);
}

static int
libxlDoMigrateSrcSend(libxlDriverPrivate *driver,
                      virDomainObj *vm,
                      unsigned int flags,
                      int sockfd)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    int xl_flags = 0;
    int ret;

    if (flags & VIR_MIGRATE_LIVE)
        xl_flags = LIBXL_SUSPEND_LIVE;

    ret = libxl_domain_suspend(cfg->ctx, vm->def->id, sockfd,
                               xl_flags, NULL);
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to send migration data to destination host"));
        ret = -1;
    }

    virObjectUnref(cfg);
    return ret;
}

static bool
libxlDomainMigrationIsAllowed(virDomainDef *def)
{
    /* Migration is not allowed if definition contains any hostdevs */
    if (def->nhostdevs > 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has assigned host devices"));
        return false;
    }

    return true;
}

char *
libxlDomainMigrationSrcBegin(virConnectPtr conn,
                             virDomainObj *vm,
                             const char *xmlin,
                             char **cookieout,
                             int *cookieoutlen)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxlMigrationCookie *mig = NULL;
    g_autoptr(virDomainDef) tmpdef = NULL;
    virDomainDef *def;
    char *xml = NULL;

    /*
     * In the case of successful migration, a job is started here and
     * terminated in the confirm phase. Errors in the begin or perform
     * phase will also terminate the job.
     */
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(mig = libxlMigrationCookieNew(vm)))
        goto endjob;

    if (libxlMigrationBakeCookie(mig, cookieout, cookieoutlen) < 0)
        goto endjob;

    if (xmlin) {
        if (!(tmpdef = virDomainDefParseString(xmlin,
                                               driver->xmlopt,
                                               NULL,
                                               VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                               VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto endjob;

        if (!libxlDomainDefCheckABIStability(driver, vm->def, tmpdef))
            goto endjob;

        def = tmpdef;
    } else {
        def = vm->def;
    }

    if (!libxlDomainMigrationIsAllowed(def))
        goto endjob;

    xml = virDomainDefFormat(def, driver->xmlopt, VIR_DOMAIN_DEF_FORMAT_SECURE);
    /* Valid xml means success! EndJob in the confirm phase */
    if (xml)
        goto cleanup;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    libxlMigrationCookieFree(mig);
    virObjectUnref(cfg);
    return xml;
}

virDomainDef *
libxlDomainMigrationDstPrepareDef(libxlDriverPrivate *driver,
                                  const char *dom_xml,
                                  const char *dname)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainDef *def;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(def = virDomainDefParseString(dom_xml, driver->xmlopt,
                                        NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (dname) {
        VIR_FREE(def->name);
        def->name = g_strdup(dname);
    }

 cleanup:
    virObjectUnref(cfg);
    return def;
}

static int
libxlDomainMigrationPrepareAny(virConnectPtr dconn,
                               virDomainDef **def,
                               const char *cookiein,
                               int cookieinlen,
                               libxlMigrationCookie **mig,
                               char **xmlout,
                               bool *taint_hook)
{
    libxlDriverPrivate *driver = dconn->privateData;

    if (libxlMigrationEatCookie(cookiein, cookieinlen, mig) < 0)
        return -1;

    if ((*mig)->xenMigStreamVer > LIBXL_SAVE_VERSION) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Xen migration stream version '%1$d' is not supported on this host"),
                       (*mig)->xenMigStreamVer);
        return -1;
    }

    /* Let migration hook filter domain XML */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        int hookret;

        hookret = libxlDomainHookRun(driver, *def,
                                     VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_MIGRATABLE,
                                     VIR_HOOK_LIBXL_OP_MIGRATE,
                                     VIR_HOOK_SUBOP_BEGIN,
                                     xmlout);

        if (hookret < 0) {
            return -1;
        } else if (hookret == 0) {
            if (virStringIsEmpty(*xmlout)) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                virDomainDef *newdef;

                VIR_DEBUG("Using hook-filtered domain XML: %s", *xmlout);
                newdef = virDomainDefParseString(*xmlout, driver->xmlopt,
                                                 NULL,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                 VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
                if (!newdef)
                    return -1;

                /* TODO At some stage we will want to have some check of what the user
                 * did in the hook. */

                virDomainDefFree(*def);
                *def = newdef;
                /* We should taint the domain here. However, @vm and therefore
                 * privateData too are still NULL, so just notice the fact and
                 * taint it later. */
                *taint_hook = true;
            }
        }
    }

    return 0;
}

int
libxlDomainMigrationDstPrepareTunnel3(virConnectPtr dconn,
                                      virStreamPtr st,
                                      virDomainDef **def,
                                      const char *cookiein,
                                      int cookieinlen,
                                      unsigned int flags)
{
    libxlMigrationCookie *mig = NULL;
    libxlDriverPrivate *driver = dconn->privateData;
    virDomainObj *vm = NULL;
    libxlMigrationDstArgs *args = NULL;
    bool taint_hook = false;
    libxlDomainObjPrivate *priv = NULL;
    char *xmlout = NULL;
    int dataFD[2] = { -1, -1 };
    int ret = -1;
    g_autofree char *name = NULL;

    if (libxlDomainMigrationPrepareAny(dconn, def, cookiein, cookieinlen,
                                       &mig, &xmlout, &taint_hook) < 0)
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;

    /*
     * Unless an error is encountered in this function, the job will
     * be terminated in the finish phase.
     */
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto error;

    priv = vm->privateData;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    /*
     * The data flow of tunnel3 migration in the dest side:
     * stream -> pipe -> recvfd of libxlDomainStartRestore
     */
    if (virPipe(dataFD) < 0)
        goto endjob;

    /* Stream data will be written to pipeIn */
    if (virFDStreamOpen(st, dataFD[1]) < 0)
        goto endjob;
    dataFD[1] = -1; /* 'st' owns the FD now & will close it */

    if (libxlMigrationDstArgsInitialize() < 0)
        goto endjob;

    if (!(args = virObjectNew(libxlMigrationDstArgsClass)))
        goto endjob;

    args->conn = virObjectRef(dconn);
    args->vm = virObjectRef(vm);
    args->flags = flags;
    args->migcookie = g_steal_pointer(&mig);
    /* Receive from pipeOut */
    args->recvfd = dataFD[0];
    args->nsocks = 0;

    VIR_FREE(priv->migrationDstReceiveThr);
    priv->migrationDstReceiveThr = g_new0(virThread, 1);
    name = g_strdup_printf("mig-%s", args->vm->def->name);
    if (virThreadCreateFull(priv->migrationDstReceiveThr, true,
                            libxlDoMigrateDstReceive,
                            name, false, args) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to create thread for receiving migration data"));
        goto endjob;
    }

    ret = 0;
    goto done;

 endjob:
    virDomainObjEndJob(vm);

 error:
    libxlMigrationCookieFree(mig);
    VIR_FORCE_CLOSE(dataFD[1]);
    VIR_FORCE_CLOSE(dataFD[0]);
    virObjectUnref(args);
    /* Remove virDomainObj from domain list */
    if (vm)
        virDomainObjListRemove(driver->domains, vm);

 done:
    virDomainObjEndAPI(&vm);
    return ret;
}

int
libxlDomainMigrationDstPrepare(virConnectPtr dconn,
                               virDomainDef **def,
                               const char *uri_in,
                               char **uri_out,
                               const char *cookiein,
                               int cookieinlen,
                               unsigned int flags)
{
    libxlDriverPrivate *driver = dconn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxlMigrationCookie *mig = NULL;
    virDomainObj *vm = NULL;
    char *hostname = NULL;
    char *xmlout = NULL;
    unsigned short port;
    char portstr[100];
    g_autoptr(virURI) uri = NULL;
    virNetSocket **socks = NULL;
    size_t nsocks = 0;
    int nsocks_listen = 0;
    libxlMigrationDstArgs *args = NULL;
    bool taint_hook = false;
    libxlDomainObjPrivate *priv = NULL;
    size_t i;
    int ret = -1;

    if (libxlDomainMigrationPrepareAny(dconn, def, cookiein, cookieinlen,
                                       &mig, &xmlout, &taint_hook) < 0)
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;

    /*
     * Unless an error is encountered in this function, the job will
     * be terminated in the finish phase.
     */
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto error;

    priv = vm->privateData;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    /* Create socket connection to receive migration data */
    if (!uri_in) {
        if ((hostname = virGetHostname()) == NULL)
            goto endjob;

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost, but migration requires an FQDN"));
            goto endjob;
        }

        if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
            goto endjob;

        priv->migrationPort = port;
        *uri_out = g_strdup_printf("tcp://%s:%d", hostname, port);
    } else {
        if (!(STRPREFIX(uri_in, "tcp://"))) {
            /* not full URI, add prefix tcp:// */
            char *tmp;
            tmp = g_strdup_printf("tcp://%s", uri_in);
            uri = virURIParse(tmp);
            VIR_FREE(tmp);
        } else {
            uri = virURIParse(uri_in);
        }

        if (uri == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to parse URI: %1$s"),
                           uri_in);
            goto endjob;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing host in migration URI: %1$s"),
                           uri_in);
            goto endjob;
        }
        hostname = uri->server;

        if (uri->port == 0) {
            if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto endjob;

            priv->migrationPort = port;
        } else {
            port = uri->port;
        }

        *uri_out = g_strdup_printf("tcp://%s:%d", hostname, port);
    }

    g_snprintf(portstr, sizeof(portstr), "%d", port);

    if (virNetSocketNewListenTCP(hostname, portstr,
                                 AF_UNSPEC,
                                 &socks, &nsocks) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Fail to create socket for incoming migration"));
        goto endjob;
    }

    if (libxlMigrationDstArgsInitialize() < 0)
        goto endjob;

    if (!(args = virObjectNew(libxlMigrationDstArgsClass)))
        goto endjob;

    args->conn = virObjectRef(dconn);
    args->vm = virObjectRef(vm);
    args->flags = flags;
    args->socks = socks;
    args->nsocks = nsocks;
    args->migcookie = g_steal_pointer(&mig);

    for (i = 0; i < nsocks; i++) {
        if (virNetSocketSetBlocking(socks[i], true) < 0)
             continue;

        if (virNetSocketListen(socks[i], 1) < 0)
            continue;

        if (virNetSocketAddIOCallback(socks[i],
                                      VIR_EVENT_HANDLE_READABLE,
                                      libxlMigrateDstReceive,
                                      virObjectRef(args),
                                      NULL) < 0)
            continue;

        nsocks_listen++;
    }

    if (!nsocks_listen)
        goto endjob;

    ret = 0;
    goto done;

 endjob:
    virDomainObjEndJob(vm);

 error:
    for (i = 0; i < nsocks; i++) {
        virNetSocketClose(socks[i]);
        virObjectUnref(socks[i]);
    }
    VIR_FREE(socks);
    if (priv) {
        virPortAllocatorRelease(priv->migrationPort);
        priv->migrationPort = 0;
    }
    /* Remove virDomainObj from domain list */
    if (vm)
        virDomainObjListRemove(driver->domains, vm);

 done:
    VIR_FREE(xmlout);
    libxlMigrationCookieFree(mig);
    if (!uri_in)
        VIR_FREE(hostname);
    virObjectUnref(args);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

typedef struct _libxlTunnelMigrationThread libxlTunnelMigrationThread;
struct _libxlTunnelMigrationThread {
    virStreamPtr st;
    int srcFD;
};
#define TUNNEL_SEND_BUF_SIZE 65536

/*
 * The data flow of tunnel3 migration in the src side:
 * libxlDoMigrateSrcSend() -> pipe
 * libxlTunnel3MigrationSrcFunc() polls pipe out and then write to dest stream.
 */
static void libxlTunnel3MigrationSrcFunc(void *arg)
{
    libxlTunnelMigrationThread *data = (libxlTunnelMigrationThread *)arg;
    g_autofree char *buffer = NULL;
    struct pollfd fds[1];
    int timeout = -1;

    buffer = g_new0(char, TUNNEL_SEND_BUF_SIZE);

    fds[0].fd = data->srcFD;
    for (;;) {
        int ret;

        fds[0].events = POLLIN;
        fds[0].revents = 0;
        ret = poll(fds, G_N_ELEMENTS(fds), timeout);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportError(errno, "%s",
                           _("poll failed in libxlTunnel3MigrationSrcFunc"));
            return;
        }

        if (ret == 0) {
            VIR_DEBUG("poll returned 0");
            break;
        }

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            int nbytes;

            nbytes = read(data->srcFD, buffer, TUNNEL_SEND_BUF_SIZE);
            if (nbytes > 0) {
                /* Write to dest stream */
                if (virStreamSend(data->st, buffer, nbytes) < 0) {
                    virStreamAbort(data->st);
                    return;
                }
            } else if (nbytes < 0) {
                virReportError(errno, "%s",
                               _("tunnelled migration failed to read from xen side"));
                virStreamAbort(data->st);
                return;
            } else {
                /* EOF; transferred all data */
                break;
            }
        }
    }

    ignore_value(virStreamFinish(data->st));
    return;
}

struct libxlTunnelControl {
    libxlTunnelMigrationThread tmThread;
    virThread thread;
    int dataFD[2];
};

static int
libxlMigrationSrcStartTunnel(libxlDriverPrivate *driver,
                             virDomainObj *vm,
                             unsigned int flags,
                             virStreamPtr st,
                             struct libxlTunnelControl **tnl)
{
    struct libxlTunnelControl *tc = NULL;
    libxlTunnelMigrationThread *arg = NULL;
    int ret = -1;
    g_autofree char *name = NULL;

    tc = g_new0(struct libxlTunnelControl, 1);
    *tnl = tc;

    tc->dataFD[0] = -1;
    tc->dataFD[1] = -1;
    if (virPipe(tc->dataFD) < 0)
        return -1;

    arg = &tc->tmThread;
    /* Read from pipe */
    arg->srcFD = tc->dataFD[0];
    /* Write to dest stream */
    arg->st = st;
    name = g_strdup_printf("mig-%s", vm->def->name);
    if (virThreadCreateFull(&tc->thread, true,
                            libxlTunnel3MigrationSrcFunc,
                            name, false, arg) < 0) {
        virReportError(errno, "%s",
                       _("Unable to create tunnel migration thread"));
        return -1;
    }

    virObjectUnlock(vm);
    /* Send data to pipe */
    ret = libxlDoMigrateSrcSend(driver, vm, flags, tc->dataFD[1]);
    virObjectLock(vm);

    /* libxlMigrationSrcStopTunnel will be called in libxlDoMigrateSrcP2P
     * to free all resources for us.
     */
    return ret;
}

static void libxlMigrationSrcStopTunnel(struct libxlTunnelControl *tc)
{
    if (!tc)
        return;

    virThreadCancel(&tc->thread);
    virThreadJoin(&tc->thread);

    VIR_FORCE_CLOSE(tc->dataFD[0]);
    VIR_FORCE_CLOSE(tc->dataFD[1]);
    VIR_FREE(tc);
}

/* This function is a simplification of virDomainMigrateVersion3Full and
 * restricting it to migration v3 with params since it was the first to be
 * introduced in libxl.
 */
static int
libxlDoMigrateSrcP2P(libxlDriverPrivate *driver,
                     virDomainObj *vm,
                     virConnectPtr sconn,
                     const char *xmlin,
                     virConnectPtr dconn,
                     const char *dconnuri G_GNUC_UNUSED,
                     const char *dname,
                     const char *uri,
                     unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    char *uri_out = NULL;
    char *dom_xml = NULL;
    unsigned long destflags;
    char *cookieout = NULL;
    int cookieoutlen;
    bool cancelled = true;
    bool notify_source = true;
    virErrorPtr orig_err = NULL;
    int ret = -1;
    /* For tunnel migration */
    virStreamPtr st = NULL;
    struct libxlTunnelControl *tc = NULL;

    if (dname &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, dname) < 0)
        goto cleanup;

    if (uri &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_URI, uri) < 0)
        goto cleanup;

    dom_xml = libxlDomainMigrationSrcBegin(sconn, vm, xmlin,
                                           &cookieout, &cookieoutlen);
    /*
     * If dom_xml is non-NULL the begin phase has succeeded, and the
     * confirm phase must be called to cleanup the migration operation.
     */
    if (!dom_xml)
        goto cleanup;

    if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_XML, dom_xml) < 0)
        goto confirm;

    /* We don't require the destination to have P2P support
     * as it looks to be normal migration from the receiver perspective.
     */
    destflags = flags & ~(VIR_MIGRATE_PEER2PEER);

    VIR_DEBUG("Prepare3");
    virObjectUnlock(vm);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        if (!(st = virStreamNew(dconn, 0)))
            goto confirm;
        ret = dconn->driver->domainMigratePrepareTunnel3Params
            (dconn, st, params, nparams, cookieout, cookieoutlen, NULL, NULL, destflags);
    } else {
        ret = dconn->driver->domainMigratePrepare3Params
            (dconn, params, nparams, cookieout, cookieoutlen, NULL, NULL, &uri_out, destflags);
    }
    virObjectLock(vm);

    if (ret == -1)
        goto confirm;

    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        if (uri_out) {
            if (virTypedParamsReplaceString(&params, &nparams,
                                            VIR_MIGRATE_PARAM_URI, uri_out) < 0) {
                virErrorPreserveLast(&orig_err);
                goto finish;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("domainMigratePrepare3 did not set uri"));
            goto finish;
        }
    }

    VIR_DEBUG("Perform3 uri=%s", NULLSTR(uri_out));
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = libxlMigrationSrcStartTunnel(driver, vm, flags, st, &tc);
    else
        ret = libxlDomainMigrationSrcPerform(driver, vm, NULL, NULL,
                                             uri_out, NULL, flags);
    if (ret < 0) {
        notify_source = false;
        virErrorPreserveLast(&orig_err);
    }

    cancelled = (ret < 0);

 finish:
    VIR_DEBUG("Finish3 ret=%d", ret);
    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, NULL) <= 0 &&
        virTypedParamsReplaceString(&params, &nparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME,
                                    vm->def->name) < 0) {
        ddomain = NULL;
    } else {
        virObjectUnlock(vm);
        ddomain = dconn->driver->domainMigrateFinish3Params
            (dconn, params, nparams, NULL, 0, NULL, NULL,
             destflags, cancelled);
        virObjectLock(vm);
    }

    cancelled = (ddomain == NULL);

    /* If Finish3Params set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        virErrorPreserveLast(&orig_err);

 confirm:
    if (notify_source) {
        VIR_DEBUG("Confirm3 cancelled=%d vm=%p", cancelled, vm);
        ret = libxlDomainMigrationSrcConfirm(driver, vm, flags, cancelled);

        if (ret < 0)
            VIR_WARN("Guest %s probably left in 'paused' state on source",
                     vm->def->name);
    }

 cleanup:
    if (flags & VIR_MIGRATE_TUNNELLED) {
        libxlMigrationSrcStopTunnel(tc);
        virObjectUnref(st);
    }

    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virErrorRestore(&orig_err);

    VIR_FREE(cookieout);
    VIR_FREE(dom_xml);
    VIR_FREE(uri_out);
    virTypedParamsFree(params, nparams);
    return ret;
}

static int virConnectCredType[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE,
};

static virConnectAuth virConnectAuthConfig = {
    .credtype = virConnectCredType,
    .ncredtype = G_N_ELEMENTS(virConnectCredType),
};

/* On P2P mode there is only the Perform3 phase and we need to handle
 * the connection with the destination libvirtd and perform the migration.
 * Here we first tackle the first part of it, and libxlDoMigrationP2P handles
 * the migration process with an established virConnectPtr to the destination.
 */
int
libxlDomainMigrationSrcPerformP2P(libxlDriverPrivate *driver,
                                  virDomainObj *vm,
                                  virConnectPtr sconn,
                                  const char *xmlin,
                                  const char *dconnuri,
                                  const char *uri_str G_GNUC_UNUSED,
                                  const char *dname,
                                  unsigned int flags)
{
    int ret = -1;
    int useParams;
    virConnectPtr dconn = NULL;
    virErrorPtr orig_err = NULL;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);

    virObjectUnlock(vm);
    dconn = virConnectOpenAuth(dconnuri, &virConnectAuthConfig, 0);
    virObjectLock(vm);

    if (dconn == NULL) {
        return ret;
    }

    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    virObjectUnlock(vm);
    useParams = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                         VIR_DRV_FEATURE_MIGRATION_PARAMS);
    virObjectLock(vm);

    if (useParams <= 0) {
        if (useParams == 0)
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Destination libvirt does not support migration with extensible parameters"));
        goto cleanup;
    }

    ret = libxlDoMigrateSrcP2P(driver, vm, sconn, xmlin, dconn, dconnuri,
                               dname, uri_str, flags);

    if (ret < 0) {
        /*
         * Confirm phase will not be executed if perform fails. End the
         * job started in begin phase.
         */
        virDomainObjEndJob(vm);
    }

 cleanup:
    virErrorPreserveLast(&orig_err);
    virObjectUnlock(vm);
    virObjectUnref(dconn);
    virObjectUnref(cfg);
    virObjectLock(vm);
    virErrorRestore(&orig_err);
    return ret;
}

int
libxlDomainMigrationSrcPerform(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               const char *dom_xml G_GNUC_UNUSED,
                               const char *dconnuri G_GNUC_UNUSED,
                               const char *uri_str,
                               const char *dname G_GNUC_UNUSED,
                               unsigned int flags)
{
    libxlDomainObjPrivate *priv = vm->privateData;
    char *hostname = NULL;
    unsigned short port = 0;
    char portstr[100];
    g_autoptr(virURI) uri = NULL;
    virNetSocket *sock;
    VIR_AUTOCLOSE sockfd = -1;
    int ret = -1;

    /* parse dst host:port from uri */
    uri = virURIParse(uri_str);
    if (uri == NULL || uri->server == NULL || uri->port == 0)
        return -1;

    hostname = uri->server;
    port = uri->port;
    g_snprintf(portstr, sizeof(portstr), "%d", port);

    /* socket connect to dst host:port */
    if (virNetSocketNewConnectTCP(hostname, portstr,
                                  AF_UNSPEC,
                                  &sock) < 0)
        return -1;

    if (virNetSocketSetBlocking(sock, true) < 0) {
        virObjectUnref(sock);
        return -1;
    }

    sockfd = virNetSocketDupFD(sock, true);
    virObjectUnref(sock);

    /* suspend vm and send saved data to dst through socket fd */
    virObjectUnlock(vm);
    ret = libxlDoMigrateSrcSend(driver, vm, flags, sockfd);
    virObjectLock(vm);

    if (ret == 0) {
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) == 0) {
            priv->lockProcessRunning = false;
            VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));
        } else {
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        }
    } else {
        /*
         * Confirm phase will not be executed if perform fails. End the
         * job started in begin phase.
         */
        virDomainObjEndJob(vm);
    }

    return ret;
}

virDomainPtr
libxlDomainMigrationDstFinish(virConnectPtr dconn,
                              virDomainObj *vm,
                              unsigned int flags,
                              int cancelled)
{
    libxlDriverPrivate *driver = dconn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event = NULL;
    virDomainPtr dom = NULL;

    if (priv->migrationDstReceiveThr) {
        virObjectUnlock(vm);
        virThreadJoin(priv->migrationDstReceiveThr);
        virObjectLock(vm);
        VIR_FREE(priv->migrationDstReceiveThr);
    }

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;

    if (cancelled)
        goto cleanup;

    /* Check if domain is alive */
    if (!virDomainObjIsActive(vm)) {
        /* Migration failed if domain is inactive */
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Migration failed. Domain is not running on destination host"));
        goto cleanup;
    }

    /* Unpause if requested */
    if (!(flags & VIR_MIGRATE_PAUSED)) {
        if (libxlDomainUnpauseWrapper(cfg->ctx, vm->def->id) != 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Failed to unpause domain"));
            goto cleanup;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_MIGRATED);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    virObjectEventStateQueue(driver->domainEventState, event);
    event = NULL;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        unsigned int oldPersist = vm->persistent;
        virDomainDef *vmdef;

        vm->persistent = 1;
        if (!(vmdef = virDomainObjGetPersistentDef(driver->xmlopt, vm, NULL)))
            goto cleanup;

        if (virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir) < 0)
            goto cleanup;

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_DEFINED,
                                         oldPersist ?
                                         VIR_DOMAIN_EVENT_DEFINED_UPDATED :
                                         VIR_DOMAIN_EVENT_DEFINED_ADDED);
        virObjectEventStateQueue(driver->domainEventState, event);
        event = NULL;
    }

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto cleanup;

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    if (dom == NULL) {
        libxlDomainDestroyInternal(driver, vm);
        libxlDomainCleanup(driver, vm);
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_FAILED);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
    }

    /* EndJob for corresponding BeginJob in prepare phase */
    virDomainObjEndJob(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return dom;
}

int
libxlDomainMigrationSrcConfirm(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               unsigned int flags,
                               int cancelled)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event = NULL;

    if (cancelled) {
        /* Resume lock process that was paused in MigrationSrcPerform */
        virDomainLockProcessResume(driver->lockManager,
                                   "xen:///system",
                                   vm,
                                   priv->lockState);
        priv->lockProcessRunning = true;
        goto cleanup;
    }

    libxlDomainDestroyInternal(driver, vm);
    libxlDomainCleanup(driver, vm);
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                         VIR_DOMAIN_SHUTOFF_MIGRATED);
    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_MIGRATED);

    VIR_DEBUG("Domain '%s' successfully migrated", vm->def->name);

    if (flags & VIR_MIGRATE_UNDEFINE_SOURCE)
        virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);

    if (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE))
        virDomainObjListRemove(driver->domains, vm);

 cleanup:
    /* EndJob for corresponding BeginJob in begin phase */
    virDomainObjEndJob(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}
