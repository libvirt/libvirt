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
 *
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 *     Chunyan Liu <cyliu@suse.com>
 */

#include <config.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "virstring.h"
#include "virobject.h"
#include "virthread.h"
#include "virhook.h"
#include "rpc/virnetsocket.h"
#include "libxl_domain.h"
#include "libxl_driver.h"
#include "libxl_conf.h"
#include "libxl_migration.h"
#include "locking/domain_lock.h"
#include "virtypedparam.h"
#include "fdstream.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_migration");

typedef struct _libxlMigrationCookie libxlMigrationCookie;
typedef libxlMigrationCookie *libxlMigrationCookiePtr;
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
    virDomainObjPtr vm;
    unsigned int flags;
    libxlMigrationCookiePtr migcookie;

    /* for freeing listen sockets */
    virNetSocketPtr *socks;
    size_t nsocks;
} libxlMigrationDstArgs;

static virClassPtr libxlMigrationDstArgsClass;


static void
libxlMigrationCookieFree(libxlMigrationCookiePtr mig)
{
    if (!mig)
        return;

    VIR_FREE(mig->srcHostname);
    VIR_FREE(mig->name);
    VIR_FREE(mig);
}

static libxlMigrationCookiePtr
libxlMigrationCookieNew(virDomainObjPtr dom)
{
    libxlMigrationCookiePtr mig = NULL;

    if (VIR_ALLOC(mig) < 0)
        goto error;

    if (VIR_STRDUP(mig->name, dom->def->name) < 0)
        goto error;

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
libxlMigrationBakeCookie(libxlMigrationCookiePtr mig,
                         char **cookieout,
                         int *cookieoutlen)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
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

    if (virBufferCheckError(&buf) < 0)
        return -1;

    *cookieout = virBufferContentAndReset(&buf);
    *cookieoutlen = strlen(*cookieout) + 1;

    VIR_DEBUG("cookielen=%d cookie=%s", *cookieoutlen, *cookieout);

    return 0;
}

static int
libxlMigrationEatCookie(const char *cookiein,
                        int cookieinlen,
                        libxlMigrationCookiePtr *migout)
{
    libxlMigrationCookiePtr mig = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *uuidstr = NULL;
    int ret = -1;

    /*
     * Assume a legacy (V1) migration stream if request came from a
     * source host without cookie support, and hence no way to
     * specify a stream version.
     */
    if (!cookiein || !cookieinlen) {
        if (VIR_ALLOC(mig) < 0)
            return -1;

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

    if (VIR_ALLOC(mig) < 0)
        return -1;

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
    ret = 0;
    goto cleanup;

 error:
    libxlMigrationCookieFree(mig);

 cleanup:
    VIR_FREE(uuidstr);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return ret;
}

static void
libxlMigrationDstArgsDispose(void *obj)
{
    libxlMigrationDstArgs *args = obj;

    libxlMigrationCookieFree(args->migcookie);
    VIR_FREE(args->socks);
}

static int
libxlMigrationDstArgsOnceInit(void)
{
    if (!(libxlMigrationDstArgsClass = virClassNew(virClassForObject(),
                                                   "libxlMigrationDstArgs",
                                                   sizeof(libxlMigrationDstArgs),
                                                   libxlMigrationDstArgsDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlMigrationDstArgs)

static void
libxlDoMigrateReceive(void *opaque)
{
    libxlMigrationDstArgs *args = opaque;
    virDomainObjPtr vm = args->vm;
    virNetSocketPtr *socks = args->socks;
    size_t nsocks = args->nsocks;
    libxlDriverPrivatePtr driver = args->conn->privateData;
    int recvfd = args->recvfd;
    size_t i;
    int ret;
    bool remove_dom = 0;

    virObjectRef(vm);
    virObjectLock(vm);
    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    /*
     * Always start the domain paused.  If needed, unpause in the
     * finish phase, after transfer of the domain is complete.
     */
    ret = libxlDomainStartRestore(driver, vm, true, recvfd,
                                  args->migcookie->xenMigStreamVer);

    if (ret < 0 && !vm->persistent)
        remove_dom = true;

    /* Remove all listen socks from event handler, and close them. */
    for (i = 0; i < nsocks; i++) {
        virNetSocketRemoveIOCallback(socks[i]);
        virNetSocketClose(socks[i]);
        virObjectUnref(socks[i]);
        socks[i] = NULL;
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);

    libxlDomainObjEndJob(driver, vm);

 cleanup:
    if (remove_dom) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }
    virDomainObjEndAPI(&vm);
}


static void
libxlMigrateReceive(virNetSocketPtr sock,
                    int events ATTRIBUTE_UNUSED,
                    void *opaque)
{
    libxlMigrationDstArgs *args = opaque;
    virNetSocketPtr *socks = args->socks;
    size_t nsocks = args->nsocks;
    virNetSocketPtr client_sock;
    int recvfd = -1;
    virThread thread;
    size_t i;

    /* Accept migration connection */
    if (virNetSocketAccept(sock, &client_sock) < 0 || !client_sock) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to accept migration connection"));
        goto fail;
    }
    VIR_DEBUG("Accepted migration connection."
              "  Spawing thread to process migration data");
    recvfd = virNetSocketDupFD(client_sock, true);
    virObjectUnref(client_sock);

    /*
     * Avoid blocking the event loop.  Start a thread to receive
     * the migration data
     */
    args->recvfd = recvfd;
    if (virThreadCreate(&thread, false,
                        libxlDoMigrateReceive, args) < 0) {
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
        virNetSocketClose(socks[i]);
        socks[i] = NULL;
    }
    args->nsocks = 0;
    VIR_FORCE_CLOSE(recvfd);
    virObjectUnref(args);
}

static int
libxlDoMigrateSend(libxlDriverPrivatePtr driver,
                   virDomainObjPtr vm,
                   unsigned long flags,
                   int sockfd)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
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
libxlDomainMigrationIsAllowed(virDomainDefPtr def)
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
libxlDomainMigrationBegin(virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *xmlin,
                          char **cookieout,
                          int *cookieoutlen)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    libxlMigrationCookiePtr mig = NULL;
    virDomainDefPtr tmpdef = NULL;
    virDomainDefPtr def;
    char *xml = NULL;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(mig = libxlMigrationCookieNew(vm)))
        goto endjob;

    if (libxlMigrationBakeCookie(mig, cookieout, cookieoutlen) < 0)
        goto endjob;

    if (xmlin) {
        if (!(tmpdef = virDomainDefParseString(xmlin, cfg->caps,
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

    xml = virDomainDefFormat(def, cfg->caps, VIR_DOMAIN_DEF_FORMAT_SECURE);

 endjob:
    libxlDomainObjEndJob(driver, vm);

 cleanup:
    libxlMigrationCookieFree(mig);
    virDomainObjEndAPI(&vm);
    virDomainDefFree(tmpdef);
    virObjectUnref(cfg);
    return xml;
}

virDomainDefPtr
libxlDomainMigrationPrepareDef(libxlDriverPrivatePtr driver,
                               const char *dom_xml,
                               const char *dname)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainDefPtr def;
    char *name = NULL;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(def = virDomainDefParseString(dom_xml, cfg->caps, driver->xmlopt,
                                        NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (dname) {
        name = def->name;
        if (VIR_STRDUP(def->name, dname) < 0) {
            virDomainDefFree(def);
            def = NULL;
        }
    }

 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(name);
    return def;
}

static int
libxlDomainMigrationPrepareAny(virConnectPtr dconn,
                               virDomainDefPtr *def,
                               const char *cookiein,
                               int cookieinlen,
                               libxlMigrationCookiePtr *mig,
                               char **xmlout,
                               bool *taint_hook)
{
    libxlDriverPrivatePtr driver = dconn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);

    if (libxlMigrationEatCookie(cookiein, cookieinlen, mig) < 0)
        return -1;

    if ((*mig)->xenMigStreamVer > LIBXL_SAVE_VERSION) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Xen migration stream version '%d' is not supported on this host"),
                       (*mig)->xenMigStreamVer);
        return -1;
    }

    /* Let migration hook filter domain XML */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml;
        int hookret;

        if (!(xml = virDomainDefFormat(*def, cfg->caps,
                                       VIR_DOMAIN_XML_SECURE |
                                       VIR_DOMAIN_XML_MIGRATABLE)))
            return -1;

        hookret = virHookCall(VIR_HOOK_DRIVER_LIBXL, (*def)->name,
                              VIR_HOOK_LIBXL_OP_MIGRATE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, xmlout);
        VIR_FREE(xml);

        if (hookret < 0) {
            return -1;
        } else if (hookret == 0) {
            if (virStringIsEmpty(*xmlout)) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                virDomainDefPtr newdef;

                VIR_DEBUG("Using hook-filtered domain XML: %s", *xmlout);
                newdef = virDomainDefParseString(*xmlout, cfg->caps, driver->xmlopt,
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
libxlDomainMigrationPrepareTunnel3(virConnectPtr dconn,
                                   virStreamPtr st,
                                   virDomainDefPtr *def,
                                   const char *cookiein,
                                   int cookieinlen,
                                   unsigned int flags)
{
    libxlMigrationCookiePtr mig = NULL;
    libxlDriverPrivatePtr driver = dconn->privateData;
    virDomainObjPtr vm = NULL;
    libxlMigrationDstArgs *args = NULL;
    virThread thread;
    bool taint_hook = false;
    libxlDomainObjPrivatePtr priv = NULL;
    char *xmlout = NULL;
    int dataFD[2] = { -1, -1 };
    int ret = -1;

    if (libxlDomainMigrationPrepareAny(dconn, def, cookiein, cookieinlen,
                                       &mig, &xmlout, &taint_hook) < 0)
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, *def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;

    *def = NULL;
    priv = vm->privateData;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    /*
     * The data flow of tunnel3 migration in the dest side:
     * stream -> pipe -> recvfd of libxlDomainStartRestore
     */
    if (pipe(dataFD) < 0)
        goto error;

    /* Stream data will be written to pipeIn */
    if (virFDStreamOpen(st, dataFD[1]) < 0)
        goto error;
    dataFD[1] = -1; /* 'st' owns the FD now & will close it */

    if (libxlMigrationDstArgsInitialize() < 0)
        goto error;

    if (!(args = virObjectNew(libxlMigrationDstArgsClass)))
        goto error;

    args->conn = dconn;
    args->vm = vm;
    args->flags = flags;
    args->migcookie = mig;
    /* Receive from pipeOut */
    args->recvfd = dataFD[0];
    args->nsocks = 0;
    mig = NULL;

    if (virThreadCreate(&thread, false, libxlDoMigrateReceive, args) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to create thread for receiving migration data"));
        goto error;
    }

    ret = 0;
    goto done;

 error:
    libxlMigrationCookieFree(mig);
    VIR_FORCE_CLOSE(dataFD[1]);
    VIR_FORCE_CLOSE(dataFD[0]);
    virObjectUnref(args);
    /* Remove virDomainObj from domain list */
    if (vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

 done:
    if (vm)
        virObjectUnlock(vm);

    return ret;
}

int
libxlDomainMigrationPrepare(virConnectPtr dconn,
                            virDomainDefPtr *def,
                            const char *uri_in,
                            char **uri_out,
                            const char *cookiein,
                            int cookieinlen,
                            unsigned int flags)
{
    libxlDriverPrivatePtr driver = dconn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    libxlMigrationCookiePtr mig = NULL;
    virDomainObjPtr vm = NULL;
    char *hostname = NULL;
    char *xmlout = NULL;
    unsigned short port;
    char portstr[100];
    virURIPtr uri = NULL;
    virNetSocketPtr *socks = NULL;
    size_t nsocks = 0;
    int nsocks_listen = 0;
    libxlMigrationDstArgs *args = NULL;
    bool taint_hook = false;
    libxlDomainObjPrivatePtr priv = NULL;
    size_t i;
    int ret = -1;

    if (libxlDomainMigrationPrepareAny(dconn, def, cookiein, cookieinlen,
                                       &mig, &xmlout, &taint_hook) < 0)
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, *def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;

    *def = NULL;
    priv = vm->privateData;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    /* Create socket connection to receive migration data */
    if (!uri_in) {
        if ((hostname = virGetHostname()) == NULL)
            goto error;

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto error;
        }

        if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
            goto error;

        priv->migrationPort = port;
        if (virAsprintf(uri_out, "tcp://%s:%d", hostname, port) < 0)
            goto error;
    } else {
        if (!(STRPREFIX(uri_in, "tcp://"))) {
            /* not full URI, add prefix tcp:// */
            char *tmp;
            if (virAsprintf(&tmp, "tcp://%s", uri_in) < 0)
                goto error;
            uri = virURIParse(tmp);
            VIR_FREE(tmp);
        } else {
            uri = virURIParse(uri_in);
        }

        if (uri == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to parse URI: %s"),
                           uri_in);
            goto error;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing host in migration URI: %s"),
                           uri_in);
            goto error;
        } else {
            hostname = uri->server;
        }

        if (uri->port == 0) {
            if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto error;

            priv->migrationPort = port;
        } else {
            port = uri->port;
        }

        if (virAsprintf(uri_out, "tcp://%s:%d", hostname, port) < 0)
            goto error;
    }

    snprintf(portstr, sizeof(portstr), "%d", port);

    if (virNetSocketNewListenTCP(hostname, portstr,
                                 AF_UNSPEC,
                                 &socks, &nsocks) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Fail to create socket for incoming migration"));
        goto error;
    }

    if (libxlMigrationDstArgsInitialize() < 0)
        goto error;

    if (!(args = virObjectNew(libxlMigrationDstArgsClass)))
        goto error;

    args->conn = dconn;
    args->vm = vm;
    args->flags = flags;
    args->socks = socks;
    args->nsocks = nsocks;
    args->migcookie = mig;
    mig = NULL;

    for (i = 0; i < nsocks; i++) {
        if (virNetSocketSetBlocking(socks[i], true) < 0)
             continue;

        if (virNetSocketListen(socks[i], 1) < 0)
            continue;

        if (virNetSocketAddIOCallback(socks[i],
                                      VIR_EVENT_HANDLE_READABLE,
                                      libxlMigrateReceive,
                                      args,
                                      NULL) < 0)
            continue;

        nsocks_listen++;
    }

    if (!nsocks_listen)
        goto error;

    ret = 0;
    goto done;

 error:
    for (i = 0; i < nsocks; i++) {
        virNetSocketClose(socks[i]);
        virObjectUnref(socks[i]);
    }
    VIR_FREE(socks);
    virObjectUnref(args);
    virPortAllocatorRelease(driver->migrationPorts, priv->migrationPort);
    priv->migrationPort = 0;

    /* Remove virDomainObj from domain list */
    if (vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

 done:
    VIR_FREE(xmlout);
    libxlMigrationCookieFree(mig);
    if (!uri_in)
        VIR_FREE(hostname);
    else
        virURIFree(uri);
    if (vm)
        virObjectUnlock(vm);
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
 * libxlDoMigrateSend() -> pipe
 * libxlTunnel3MigrationFunc() polls pipe out and then write to dest stream.
 */
static void libxlTunnel3MigrationFunc(void *arg)
{
    libxlTunnelMigrationThread *data = (libxlTunnelMigrationThread *)arg;
    char *buffer = NULL;
    struct pollfd fds[1];
    int timeout = -1;

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0)
        return;

    fds[0].fd = data->srcFD;
    for (;;) {
        int ret;

        fds[0].events = POLLIN;
        fds[0].revents = 0;
        ret = poll(fds, ARRAY_CARDINALITY(fds), timeout);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportError(errno, "%s",
                           _("poll failed in libxlTunnel3MigrationFunc"));
            goto cleanup;
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
                    goto cleanup;
                }
            } else if (nbytes < 0) {
                virReportError(errno, "%s",
                               _("tunnelled migration failed to read from xen side"));
                virStreamAbort(data->st);
                goto cleanup;
            } else {
                /* EOF; transferred all data */
                break;
            }
        }
    }

    ignore_value(virStreamFinish(data->st));

 cleanup:
    VIR_FREE(buffer);

    return;
}

struct libxlTunnelControl {
    libxlTunnelMigrationThread tmThread;
    virThread thread;
    int dataFD[2];
};

static int
libxlMigrationStartTunnel(libxlDriverPrivatePtr driver,
                          virDomainObjPtr vm,
                          unsigned long flags,
                          virStreamPtr st,
                          struct libxlTunnelControl **tnl)
{
    struct libxlTunnelControl *tc = NULL;
    libxlTunnelMigrationThread *arg = NULL;
    int ret = -1;

    if (VIR_ALLOC(tc) < 0)
        goto out;
    *tnl = tc;

    tc->dataFD[0] = -1;
    tc->dataFD[1] = -1;
    if (pipe(tc->dataFD) < 0) {
        virReportError(errno, "%s", _("Unable to make pipes"));
        goto out;
    }

    arg = &tc->tmThread;
    /* Read from pipe */
    arg->srcFD = tc->dataFD[0];
    /* Write to dest stream */
    arg->st = st;
    if (virThreadCreate(&tc->thread, true,
                        libxlTunnel3MigrationFunc, arg) < 0) {
        virReportError(errno, "%s",
                       _("Unable to create tunnel migration thread"));
        goto out;
    }

    virObjectUnlock(vm);
    /* Send data to pipe */
    ret = libxlDoMigrateSend(driver, vm, flags, tc->dataFD[1]);
    virObjectLock(vm);

 out:
    /* libxlMigrationStopTunnel will be called in libxlDoMigrateP2P to free
     * all resources for us. */
    return ret;
}

static void libxlMigrationStopTunnel(struct libxlTunnelControl *tc)
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
libxlDoMigrateP2P(libxlDriverPrivatePtr driver,
                  virDomainObjPtr vm,
                  virConnectPtr sconn,
                  const char *xmlin,
                  virConnectPtr dconn,
                  const char *dconnuri ATTRIBUTE_UNUSED,
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
    virErrorPtr orig_err = NULL;
    int ret = -1;
    /* For tunnel migration */
    virStreamPtr st = NULL;
    struct libxlTunnelControl *tc = NULL;

    dom_xml = libxlDomainMigrationBegin(sconn, vm, xmlin,
                                        &cookieout, &cookieoutlen);
    if (!dom_xml)
        goto cleanup;

    if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_XML, dom_xml) < 0)
        goto cleanup;

    if (dname &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, dname) < 0)
        goto cleanup;

    if (uri &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_URI, uri) < 0)
        goto cleanup;

    /* We don't require the destination to have P2P support
     * as it looks to be normal migration from the receiver perpective.
     */
    destflags = flags & ~(VIR_MIGRATE_PEER2PEER);

    VIR_DEBUG("Prepare3");
    virObjectUnlock(vm);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;
        ret = dconn->driver->domainMigratePrepareTunnel3Params
            (dconn, st, params, nparams, cookieout, cookieoutlen, NULL, NULL, destflags);
    } else {
        ret = dconn->driver->domainMigratePrepare3Params
            (dconn, params, nparams, cookieout, cookieoutlen, NULL, NULL, &uri_out, destflags);
    }
    virObjectLock(vm);

    if (ret == -1)
        goto cleanup;

    if (!(flags & VIR_MIGRATE_TUNNELLED)) {
        if (uri_out) {
            if (virTypedParamsReplaceString(&params, &nparams,
                                            VIR_MIGRATE_PARAM_URI, uri_out) < 0) {
                orig_err = virSaveLastError();
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
        ret = libxlMigrationStartTunnel(driver, vm, flags, st, &tc);
    else
        ret = libxlDomainMigrationPerform(driver, vm, NULL, NULL,
                                          uri_out, NULL, flags);
    if (ret < 0)
        orig_err = virSaveLastError();

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
        orig_err = virSaveLastError();

    VIR_DEBUG("Confirm3 cancelled=%d vm=%p", cancelled, vm);
    ret = libxlDomainMigrationConfirm(driver, vm, flags, cancelled);

    if (ret < 0)
        VIR_WARN("Guest %s probably left in 'paused' state on source",
                 vm->def->name);

 cleanup:
    if (flags & VIR_MIGRATE_TUNNELLED) {
        libxlMigrationStopTunnel(tc);
        virObjectUnref(st);
    }

    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

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
    .ncredtype = ARRAY_CARDINALITY(virConnectCredType),
};

/* On P2P mode there is only the Perform3 phase and we need to handle
 * the connection with the destination libvirtd and perform the migration.
 * Here we first tackle the first part of it, and libxlDoMigrationP2P handles
 * the migration process with an established virConnectPtr to the destination.
 */
int
libxlDomainMigrationPerformP2P(libxlDriverPrivatePtr driver,
                               virDomainObjPtr vm,
                               virConnectPtr sconn,
                               const char *xmlin,
                               const char *dconnuri,
                               const char *uri_str ATTRIBUTE_UNUSED,
                               const char *dname,
                               unsigned int flags)
{
    int ret = -1;
    bool useParams;
    virConnectPtr dconn = NULL;
    virErrorPtr orig_err = NULL;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);

    virObjectUnlock(vm);
    dconn = virConnectOpenAuth(dconnuri, &virConnectAuthConfig, 0);
    virObjectLock(vm);

    if (dconn == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to connect to remote libvirt URI %s: %s"),
                       dconnuri, virGetLastErrorMessage());
        return ret;
    }

    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    virObjectUnlock(vm);
    useParams = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                         VIR_DRV_FEATURE_MIGRATION_PARAMS);
    virObjectLock(vm);

    if (!useParams) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Destination libvirt does not support migration with extensible parameters"));
        goto cleanup;
    }

    ret = libxlDoMigrateP2P(driver, vm, sconn, xmlin, dconn, dconnuri,
                            dname, uri_str, flags);

 cleanup:
    orig_err = virSaveLastError();
    virObjectUnlock(vm);
    virObjectUnref(dconn);
    virObjectUnref(cfg);
    virObjectLock(vm);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    return ret;
}

int
libxlDomainMigrationPerform(libxlDriverPrivatePtr driver,
                            virDomainObjPtr vm,
                            const char *dom_xml ATTRIBUTE_UNUSED,
                            const char *dconnuri ATTRIBUTE_UNUSED,
                            const char *uri_str,
                            const char *dname ATTRIBUTE_UNUSED,
                            unsigned int flags)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    char *hostname = NULL;
    unsigned short port = 0;
    char portstr[100];
    virURIPtr uri = NULL;
    virNetSocketPtr sock;
    int sockfd = -1;
    int ret = -1;

    /* parse dst host:port from uri */
    uri = virURIParse(uri_str);
    if (uri == NULL || uri->server == NULL || uri->port == 0)
        goto cleanup;

    hostname = uri->server;
    port = uri->port;
    snprintf(portstr, sizeof(portstr), "%d", port);

    /* socket connect to dst host:port */
    if (virNetSocketNewConnectTCP(hostname, portstr,
                                  AF_UNSPEC,
                                  &sock) < 0)
        goto cleanup;

    if (virNetSocketSetBlocking(sock, true) < 0) {
        virObjectUnref(sock);
        goto cleanup;
    }

    sockfd = virNetSocketDupFD(sock, true);
    virObjectUnref(sock);

    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

    /* suspend vm and send saved data to dst through socket fd */
    virObjectUnlock(vm);
    ret = libxlDoMigrateSend(driver, vm, flags, sockfd);
    virObjectLock(vm);

 cleanup:
    VIR_FORCE_CLOSE(sockfd);
    virURIFree(uri);
    return ret;
}

virDomainPtr
libxlDomainMigrationFinish(virConnectPtr dconn,
                           virDomainObjPtr vm,
                           unsigned int flags,
                           int cancelled)
{
    libxlDriverPrivatePtr driver = dconn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    virDomainPtr dom = NULL;

    virPortAllocatorRelease(driver->migrationPorts, priv->migrationPort);
    priv->migrationPort = 0;

    if (cancelled)
        goto cleanup;

    /* Check if domain is alive */
    if (!virDomainObjIsActive(vm)) {
        /* Migration failed if domain is inactive */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Migration failed. Domain is not running "
                               "on destination host"));
        goto cleanup;
    }

    /* Unpause if requested */
    if (!(flags & VIR_MIGRATE_PAUSED)) {
        if (libxl_domain_unpause(cfg->ctx, vm->def->id) != 0) {
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

    if (event) {
        libxlDomainEventQueue(driver, event);
        event = NULL;
    }

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        unsigned int oldPersist = vm->persistent;
        virDomainDefPtr vmdef;

        vm->persistent = 1;
        if (!(vmdef = virDomainObjGetPersistentDef(cfg->caps,
                                                   driver->xmlopt, vm)))
            goto cleanup;

        if (virDomainSaveConfig(cfg->configDir, cfg->caps, vmdef) < 0)
            goto cleanup;

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_DEFINED,
                                         oldPersist ?
                                         VIR_DOMAIN_EVENT_DEFINED_UPDATED :
                                         VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event) {
            libxlDomainEventQueue(driver, event);
            event = NULL;
        }
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, cfg->caps) < 0)
        goto cleanup;

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid);

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

    if (event)
        libxlDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return dom;
}

int
libxlDomainMigrationConfirm(libxlDriverPrivatePtr driver,
                            virDomainObjPtr vm,
                            unsigned int flags,
                            int cancelled)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (cancelled) {
        if (libxl_domain_resume(cfg->ctx, vm->def->id, 1, 0) == 0) {
            ret = 0;
        } else {
            VIR_DEBUG("Unable to resume domain '%s' after failed migration",
                      vm->def->name);
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_MIGRATION);
            event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                     VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
            ignore_value(virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, cfg->caps));
        }
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

    if (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE)) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    if (event)
        libxlDomainEventQueue(driver, event);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}
