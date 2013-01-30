
/*
 * qemu_migration.c: QEMU migration handling
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include <sys/time.h>
#ifdef WITH_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif
#include <fcntl.h>
#include <poll.h>

#include "qemu_migration.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_capabilities.h"
#include "qemu_command.h"
#include "qemu_cgroup.h"

#include "domain_audit.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virutil.h"
#include "virfile.h"
#include "datatypes.h"
#include "fdstream.h"
#include "viruuid.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "rpc/virnetsocket.h"
#include "virstoragefile.h"
#include "viruri.h"
#include "virhook.h"


#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_ENUM_IMPL(qemuMigrationJobPhase, QEMU_MIGRATION_PHASE_LAST,
              "none",
              "perform2",
              "begin3",
              "perform3",
              "perform3_done",
              "confirm3_cancelled",
              "confirm3",
              "prepare",
              "finish2",
              "finish3",
);

enum qemuMigrationCookieFlags {
    QEMU_MIGRATION_COOKIE_FLAG_GRAPHICS,
    QEMU_MIGRATION_COOKIE_FLAG_LOCKSTATE,
    QEMU_MIGRATION_COOKIE_FLAG_PERSISTENT,
    QEMU_MIGRATION_COOKIE_FLAG_NETWORK,
    QEMU_MIGRATION_COOKIE_FLAG_NBD,

    QEMU_MIGRATION_COOKIE_FLAG_LAST
};

VIR_ENUM_DECL(qemuMigrationCookieFlag);
VIR_ENUM_IMPL(qemuMigrationCookieFlag,
              QEMU_MIGRATION_COOKIE_FLAG_LAST,
              "graphics",
              "lockstate",
              "persistent",
              "network",
              "nbd");

enum qemuMigrationCookieFeatures {
    QEMU_MIGRATION_COOKIE_GRAPHICS  = (1 << QEMU_MIGRATION_COOKIE_FLAG_GRAPHICS),
    QEMU_MIGRATION_COOKIE_LOCKSTATE = (1 << QEMU_MIGRATION_COOKIE_FLAG_LOCKSTATE),
    QEMU_MIGRATION_COOKIE_PERSISTENT = (1 << QEMU_MIGRATION_COOKIE_FLAG_PERSISTENT),
    QEMU_MIGRATION_COOKIE_NETWORK = (1 << QEMU_MIGRATION_COOKIE_FLAG_NETWORK),
    QEMU_MIGRATION_COOKIE_NBD = (1 << QEMU_MIGRATION_COOKIE_FLAG_NBD),
};

typedef struct _qemuMigrationCookieGraphics qemuMigrationCookieGraphics;
typedef qemuMigrationCookieGraphics *qemuMigrationCookieGraphicsPtr;
struct _qemuMigrationCookieGraphics {
    int type;
    int port;
    int tlsPort;
    char *listen;
    char *tlsSubject;
};

typedef struct _qemuMigrationCookieNetData qemuMigrationCookieNetData;
typedef qemuMigrationCookieNetData *qemuMigrationCookieNetDataPtr;
struct _qemuMigrationCookieNetData {
    int vporttype; /* enum virNetDevVPortProfile */

    /*
     * Array of pointers to saved data. Each VIF will have it's own
     * data to transfer.
     */
    char *portdata;
};

typedef struct _qemuMigrationCookieNetwork qemuMigrationCookieNetwork;
typedef qemuMigrationCookieNetwork *qemuMigrationCookieNetworkPtr;
struct _qemuMigrationCookieNetwork {
    /* How many virtual NICs are we saving data for? */
    int nnets;

    qemuMigrationCookieNetDataPtr net;
};

typedef struct _qemuMigrationCookieNBD qemuMigrationCookieNBD;
typedef qemuMigrationCookieNBD *qemuMigrationCookieNBDPtr;
struct _qemuMigrationCookieNBD {
    int port; /* on which port does NBD server listen for incoming data */
};

typedef struct _qemuMigrationCookie qemuMigrationCookie;
typedef qemuMigrationCookie *qemuMigrationCookiePtr;
struct _qemuMigrationCookie {
    unsigned int flags;
    unsigned int flagsMandatory;

    /* Host properties */
    unsigned char localHostuuid[VIR_UUID_BUFLEN];
    unsigned char remoteHostuuid[VIR_UUID_BUFLEN];
    char *localHostname;
    char *remoteHostname;

    /* Guest properties */
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;

    /* If (flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) */
    char *lockState;
    char *lockDriver;

    /* If (flags & QEMU_MIGRATION_COOKIE_GRAPHICS) */
    qemuMigrationCookieGraphicsPtr graphics;

    /* If (flags & QEMU_MIGRATION_COOKIE_PERSISTENT) */
    virDomainDefPtr persistent;

    /* If (flags & QEMU_MIGRATION_COOKIE_NETWORK) */
    qemuMigrationCookieNetworkPtr network;

    /* If (flags & QEMU_MIGRATION_COOKIE_NBD) */
    qemuMigrationCookieNBDPtr nbd;
};

static void qemuMigrationCookieGraphicsFree(qemuMigrationCookieGraphicsPtr grap)
{
    if (!grap)
        return;
    VIR_FREE(grap->listen);
    VIR_FREE(grap->tlsSubject);
    VIR_FREE(grap);
}


static void
qemuMigrationCookieNetworkFree(qemuMigrationCookieNetworkPtr network)
{
    int i;

    if (!network)
        return;

    if (network->net) {
        for (i = 0; i < network->nnets; i++)
            VIR_FREE(network->net[i].portdata);
    }
    VIR_FREE(network->net);
    VIR_FREE(network);
}


static void qemuMigrationCookieFree(qemuMigrationCookiePtr mig)
{
    if (!mig)
        return;

    if (mig->flags & QEMU_MIGRATION_COOKIE_GRAPHICS)
        qemuMigrationCookieGraphicsFree(mig->graphics);

    if (mig->flags & QEMU_MIGRATION_COOKIE_NETWORK)
        qemuMigrationCookieNetworkFree(mig->network);

    VIR_FREE(mig->localHostname);
    VIR_FREE(mig->remoteHostname);
    VIR_FREE(mig->name);
    VIR_FREE(mig->lockState);
    VIR_FREE(mig->lockDriver);
    VIR_FREE(mig->nbd);
    VIR_FREE(mig);
}


#ifdef WITH_GNUTLS
static char *
qemuDomainExtractTLSSubject(const char *certdir)
{
    char *certfile = NULL;
    char *subject = NULL;
    char *pemdata = NULL;
    gnutls_datum_t pemdatum;
    gnutls_x509_crt_t cert;
    int ret;
    size_t subjectlen;

    if (virAsprintf(&certfile, "%s/server-cert.pem", certdir) < 0)
        goto no_memory;

    if (virFileReadAll(certfile, 8192, &pemdata) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to read server cert %s"), certfile);
        goto error;
    }

    ret = gnutls_x509_crt_init(&cert);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot initialize cert object: %s"),
                       gnutls_strerror(ret));
        goto error;
    }

    pemdatum.data = (unsigned char *)pemdata;
    pemdatum.size = strlen(pemdata);

    ret = gnutls_x509_crt_import(cert, &pemdatum, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot load cert data from %s: %s"),
                       certfile, gnutls_strerror(ret));
        goto error;
    }

    subjectlen = 1024;
    if (VIR_ALLOC_N(subject, subjectlen+1) < 0)
        goto no_memory;

    gnutls_x509_crt_get_dn(cert, subject, &subjectlen);
    subject[subjectlen] = '\0';

    VIR_FREE(certfile);
    VIR_FREE(pemdata);

    return subject;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(certfile);
    VIR_FREE(pemdata);
    return NULL;
}
#endif

static qemuMigrationCookieGraphicsPtr
qemuMigrationCookieGraphicsAlloc(virQEMUDriverPtr driver,
                                 virDomainGraphicsDefPtr def)
{
    qemuMigrationCookieGraphicsPtr mig = NULL;
    const char *listenAddr;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (VIR_ALLOC(mig) < 0)
        goto no_memory;

    mig->type = def->type;
    if (mig->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        mig->port = def->data.vnc.port;
        listenAddr = virDomainGraphicsListenGetAddress(def, 0);
        if (!listenAddr)
            listenAddr = cfg->vncListen;

#ifdef WITH_GNUTLS
        if (cfg->vncTLS &&
            !(mig->tlsSubject = qemuDomainExtractTLSSubject(cfg->vncTLSx509certdir)))
            goto error;
#endif
    } else {
        mig->port = def->data.spice.port;
        if (cfg->spiceTLS)
            mig->tlsPort = def->data.spice.tlsPort;
        else
            mig->tlsPort = -1;
        listenAddr = virDomainGraphicsListenGetAddress(def, 0);
        if (!listenAddr)
            listenAddr = cfg->spiceListen;

#ifdef WITH_GNUTLS
        if (cfg->spiceTLS &&
            !(mig->tlsSubject = qemuDomainExtractTLSSubject(cfg->spiceTLSx509certdir)))
            goto error;
#endif
    }
    if (!(mig->listen = strdup(listenAddr)))
        goto no_memory;

    virObjectUnref(cfg);
    return mig;

no_memory:
    virReportOOMError();
#ifdef WITH_GNUTLS
error:
#endif
    qemuMigrationCookieGraphicsFree(mig);
    virObjectUnref(cfg);
    return NULL;
}


static qemuMigrationCookieNetworkPtr
qemuMigrationCookieNetworkAlloc(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                                virDomainDefPtr def)
{
    qemuMigrationCookieNetworkPtr mig;
    int i;

    if (VIR_ALLOC(mig) < 0)
        goto no_memory;

    mig->nnets = def->nnets;

    if (VIR_ALLOC_N(mig->net, def->nnets) <0)
        goto no_memory;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr netptr;
        virNetDevVPortProfilePtr vport;

        netptr = def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(netptr);

        if (vport) {
            mig->net[i].vporttype = vport->virtPortType;

            switch (vport->virtPortType) {
            case VIR_NETDEV_VPORT_PROFILE_NONE:
            case VIR_NETDEV_VPORT_PROFILE_8021QBG:
            case VIR_NETDEV_VPORT_PROFILE_8021QBH:
               break;
            case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
                if (virNetDevOpenvswitchGetMigrateData(&mig->net[i].portdata,
                                                       netptr->ifname) != 0) {
                        virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                                             _("Unable to run command to get OVS port data for "
                                             "interface %s"), netptr->ifname);
                        goto error;
                }
                break;
            default:
                break;
            }
        }
    }
    return mig;

no_memory:
    virReportOOMError();
error:
    qemuMigrationCookieNetworkFree(mig);
    return NULL;
}

static qemuMigrationCookiePtr
qemuMigrationCookieNew(virDomainObjPtr dom)
{
    qemuDomainObjPrivatePtr priv = dom->privateData;
    qemuMigrationCookiePtr mig = NULL;
    const char *name;

    if (VIR_ALLOC(mig) < 0)
        goto no_memory;

    if (priv->origname)
        name = priv->origname;
    else
        name = dom->def->name;
    if (!(mig->name = strdup(name)))
        goto no_memory;
    memcpy(mig->uuid, dom->def->uuid, VIR_UUID_BUFLEN);

    if (!(mig->localHostname = virGetHostname(NULL)))
        goto error;
    if (virGetHostUUID(mig->localHostuuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain host UUID"));
        goto error;
    }

    return mig;

no_memory:
    virReportOOMError();
error:
    qemuMigrationCookieFree(mig);
    return NULL;
}


static int
qemuMigrationCookieAddGraphics(qemuMigrationCookiePtr mig,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr dom)
{
    if (mig->flags & QEMU_MIGRATION_COOKIE_GRAPHICS) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration graphics data already present"));
        return -1;
    }

    if (dom->def->ngraphics == 1 &&
        (dom->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC ||
         dom->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE)) {
        if (!(mig->graphics =
              qemuMigrationCookieGraphicsAlloc(driver, dom->def->graphics[0])))
            return -1;
        mig->flags |= QEMU_MIGRATION_COOKIE_GRAPHICS;
    }

    return 0;
}


static int
qemuMigrationCookieAddLockstate(qemuMigrationCookiePtr mig,
                                virQEMUDriverPtr driver,
                                virDomainObjPtr dom)
{
    qemuDomainObjPrivatePtr priv = dom->privateData;

    if (mig->flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration lockstate data already present"));
        return -1;
    }

    if (virDomainObjGetState(dom, NULL) == VIR_DOMAIN_PAUSED) {
        if (priv->lockState &&
            !(mig->lockState = strdup(priv->lockState)))
            return -1;
    } else {
        if (virDomainLockProcessInquire(driver->lockManager, dom, &mig->lockState) < 0)
            return -1;
    }

    if (!(mig->lockDriver = strdup(virLockManagerPluginGetName(driver->lockManager)))) {
        VIR_FREE(mig->lockState);
        return -1;
    }

    mig->flags |= QEMU_MIGRATION_COOKIE_LOCKSTATE;
    mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_LOCKSTATE;

    return 0;
}


static int
qemuMigrationCookieAddPersistent(qemuMigrationCookiePtr mig,
                                 virDomainObjPtr dom)
{
    if (mig->flags & QEMU_MIGRATION_COOKIE_PERSISTENT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration persistent data already present"));
        return -1;
    }

    if (!dom->newDef)
        return 0;

    mig->persistent = dom->newDef;
    mig->flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;
    mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_PERSISTENT;
    return 0;
}


static int
qemuMigrationCookieAddNetwork(qemuMigrationCookiePtr mig,
                              virQEMUDriverPtr driver,
                              virDomainObjPtr dom)
{
    if (mig->flags & QEMU_MIGRATION_COOKIE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Network migration data already present"));
        return -1;
    }

    if (dom->def->nnets > 0) {
        mig->network = qemuMigrationCookieNetworkAlloc(driver, dom->def);
        if (!mig->network)
            return -1;
        mig->flags |= QEMU_MIGRATION_COOKIE_NETWORK;
    }

    return 0;
}


static int
qemuMigrationCookieAddNBD(qemuMigrationCookiePtr mig,
                          virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    /* It is not a bug if there already is a NBD data */
    if (!mig->nbd &&
        VIR_ALLOC(mig->nbd) < 0) {
        virReportOOMError();
        return -1;
    }

    mig->nbd->port = priv->nbdPort;
    mig->flags |= QEMU_MIGRATION_COOKIE_NBD;

    return 0;
}


static void qemuMigrationCookieGraphicsXMLFormat(virBufferPtr buf,
                                                 qemuMigrationCookieGraphicsPtr grap)
{
    virBufferAsprintf(buf, "  <graphics type='%s' port='%d' listen='%s'",
                      virDomainGraphicsTypeToString(grap->type),
                      grap->port, grap->listen);
    if (grap->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
        virBufferAsprintf(buf, " tlsPort='%d'", grap->tlsPort);
    if (grap->tlsSubject) {
        virBufferAddLit(buf, ">\n");
        virBufferEscapeString(buf, "    <cert info='subject' value='%s'/>\n", grap->tlsSubject);
        virBufferAddLit(buf, "  </graphics>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


static void
qemuMigrationCookieNetworkXMLFormat(virBufferPtr buf,
                                    qemuMigrationCookieNetworkPtr optr)
{
    int i;
    bool empty = true;

    for (i = 0; i < optr->nnets; i++) {
        /* If optr->net[i].vporttype is not set, there is nothing to transfer */
        if (optr->net[i].vporttype != VIR_NETDEV_VPORT_PROFILE_NONE) {
            if (empty) {
                virBufferAsprintf(buf, "  <network>\n");
                empty = false;
            }
            virBufferAsprintf(buf, "    <interface index='%d' vporttype='%s'",
                              i, virNetDevVPortTypeToString(optr->net[i].vporttype));
            if (optr->net[i].portdata) {
                virBufferAddLit(buf, ">\n");
                virBufferEscapeString(buf, "      <portdata>%s</portdata>\n",
                                      optr->net[i].portdata);
                virBufferAddLit(buf, "    </interface>\n");
            } else {
                virBufferAddLit(buf, "/>\n");
            }
        }
    }
    if (!empty)
        virBufferAddLit(buf, "  </network>\n");
}


static int
qemuMigrationCookieXMLFormat(virQEMUDriverPtr driver,
                             virBufferPtr buf,
                             qemuMigrationCookiePtr mig)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char hostuuidstr[VIR_UUID_STRING_BUFLEN];
    int i;

    virUUIDFormat(mig->uuid, uuidstr);
    virUUIDFormat(mig->localHostuuid, hostuuidstr);

    virBufferAsprintf(buf, "<qemu-migration>\n");
    virBufferEscapeString(buf, "  <name>%s</name>\n", mig->name);
    virBufferAsprintf(buf, "  <uuid>%s</uuid>\n", uuidstr);
    virBufferEscapeString(buf, "  <hostname>%s</hostname>\n", mig->localHostname);
    virBufferAsprintf(buf, "  <hostuuid>%s</hostuuid>\n", hostuuidstr);

    for (i = 0 ; i < QEMU_MIGRATION_COOKIE_FLAG_LAST ; i++) {
        if (mig->flagsMandatory & (1 << i))
            virBufferAsprintf(buf, "  <feature name='%s'/>\n",
                              qemuMigrationCookieFlagTypeToString(i));
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_GRAPHICS) &&
        mig->graphics)
        qemuMigrationCookieGraphicsXMLFormat(buf, mig->graphics);

    if ((mig->flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) &&
        mig->lockState) {
        virBufferAsprintf(buf, "  <lockstate driver='%s'>\n",
                          mig->lockDriver);
        virBufferAsprintf(buf, "    <leases>%s</leases>\n",
                          mig->lockState);
        virBufferAddLit(buf, "  </lockstate>\n");
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_PERSISTENT) &&
        mig->persistent) {
        virBufferAdjustIndent(buf, 2);
        if (qemuDomainDefFormatBuf(driver,
                                   mig->persistent,
                                   VIR_DOMAIN_XML_INACTIVE |
                                   VIR_DOMAIN_XML_SECURE |
                                   VIR_DOMAIN_XML_MIGRATABLE,
                                   buf) < 0)
            return -1;
        virBufferAdjustIndent(buf, -2);
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_NETWORK) && mig->network)
        qemuMigrationCookieNetworkXMLFormat(buf, mig->network);

    if ((mig->flags & QEMU_MIGRATION_COOKIE_NBD) && mig->nbd) {
        virBufferAddLit(buf, "  <nbd");
        if (mig->nbd->port)
            virBufferAsprintf(buf, " port='%d'", mig->nbd->port);
        virBufferAddLit(buf, "/>\n");
    }

    virBufferAddLit(buf, "</qemu-migration>\n");
    return 0;
}


static char *qemuMigrationCookieXMLFormatStr(virQEMUDriverPtr driver,
                                             qemuMigrationCookiePtr mig)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (qemuMigrationCookieXMLFormat(driver, &buf, mig) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


static qemuMigrationCookieGraphicsPtr
qemuMigrationCookieGraphicsXMLParse(xmlXPathContextPtr ctxt)
{
    qemuMigrationCookieGraphicsPtr grap;
    char *tmp;

    if (VIR_ALLOC(grap) < 0)
        goto no_memory;

    if (!(tmp = virXPathString("string(./graphics/@type)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing type attribute in migration data"));
        goto error;
    }
    if ((grap->type = virDomainGraphicsTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown graphics type %s"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    VIR_FREE(tmp);
    if (virXPathInt("string(./graphics/@port)", ctxt, &grap->port) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing port attribute in migration data"));
        goto error;
    }
    if (grap->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        if (virXPathInt("string(./graphics/@tlsPort)", ctxt, &grap->tlsPort) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing tlsPort attribute in migration data"));
            goto error;
        }
    }
    if (!(grap->listen = virXPathString("string(./graphics/@listen)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing listen attribute in migration data"));
        goto error;
    }
    /* Optional */
    grap->tlsSubject = virXPathString("string(./graphics/cert[@info='subject']/@value)", ctxt);

    return grap;

no_memory:
    virReportOOMError();
error:
    qemuMigrationCookieGraphicsFree(grap);
    return NULL;
}


static qemuMigrationCookieNetworkPtr
qemuMigrationCookieNetworkXMLParse(xmlXPathContextPtr ctxt)
{
    qemuMigrationCookieNetworkPtr optr;
    int i;
    int n;
    xmlNodePtr *interfaces = NULL;
    char *vporttype;
    xmlNodePtr save_ctxt = ctxt->node;

    if (VIR_ALLOC(optr) < 0)
        goto no_memory;

    if ((n = virXPathNodeSet("./network/interface", ctxt, &interfaces)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing interface information"));
        goto error;
    }

    optr->nnets = n;
    if (VIR_ALLOC_N(optr->net, optr->nnets) < 0)
        goto no_memory;

    for (i = 0; i < n; i++) {
        /* portdata is optional, and may not exist */
        ctxt->node = interfaces[i];
        optr->net[i].portdata = virXPathString("string(./portdata[1])", ctxt);

        if (!(vporttype = virXMLPropString(interfaces[i], "vporttype"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing vporttype attribute in migration data"));
            goto error;
        }
        optr->net[i].vporttype = virNetDevVPortTypeFromString(vporttype);
    }

    VIR_FREE(interfaces);

cleanup:
    ctxt->node = save_ctxt;
    return optr;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(interfaces);
    qemuMigrationCookieNetworkFree(optr);
    optr = NULL;
    goto cleanup;
}


static int
qemuMigrationCookieXMLParse(qemuMigrationCookiePtr mig,
                            virQEMUDriverPtr driver,
                            xmlDocPtr doc,
                            xmlXPathContextPtr ctxt,
                            unsigned int flags)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *tmp = NULL;
    xmlNodePtr *nodes = NULL;
    int i, n;
    virCapsPtr caps = NULL;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto error;

    /* We don't store the uuid, name, hostname, or hostuuid
     * values. We just compare them to local data to do some
     * sanity checking on migration operation
     */

    /* Extract domain name */
    if (!(tmp = virXPathString("string(./name[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing name element in migration data"));
        goto error;
    }
    if (STRNEQ(tmp, mig->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Incoming cookie data had unexpected name %s vs %s"),
                       tmp, mig->name);
        goto error;
    }
    VIR_FREE(tmp);

    /* Extract domain uuid */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing uuid element in migration data"));
        goto error;
    }
    virUUIDFormat(mig->uuid, uuidstr);
    if (STRNEQ(tmp, uuidstr)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Incoming cookie data had unexpected UUID %s vs %s"),
                       tmp, uuidstr);
    }
    VIR_FREE(tmp);

    /* Check & forbid "localhost" migration */
    if (!(mig->remoteHostname = virXPathString("string(./hostname[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing hostname element in migration data"));
        goto error;
    }
    if (STREQ(mig->remoteHostname, mig->localHostname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Attempt to migrate guest to the same host %s"),
                       mig->remoteHostname);
        goto error;
    }

    if (!(tmp = virXPathString("string(./hostuuid[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing hostuuid element in migration data"));
        goto error;
    }
    if (virUUIDParse(tmp, mig->remoteHostuuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed hostuuid element in migration data"));
        goto error;
    }
    if (memcmp(mig->remoteHostuuid, mig->localHostuuid, VIR_UUID_BUFLEN) == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Attempt to migrate guest to the same host %s"),
                       tmp);
        goto error;
    }
    VIR_FREE(tmp);

    /* Check to ensure all mandatory features from XML are also
     * present in 'flags' */
    if ((n = virXPathNodeSet("./feature", ctxt, &nodes)) < 0)
        goto error;

    for (i = 0 ; i < n ; i++) {
        int val;
        char *str = virXMLPropString(nodes[i], "name");
        if (!str) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing feature name"));
            goto error;
        }

        if ((val = qemuMigrationCookieFlagTypeFromString(str)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown migration cookie feature %s"),
                           str);
            VIR_FREE(str);
            goto error;
        }

        if ((flags & (1 << val)) == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unsupported migration cookie feature %s"),
                           str);
            VIR_FREE(str);
        }
        VIR_FREE(str);
    }
    VIR_FREE(nodes);

    if ((flags & QEMU_MIGRATION_COOKIE_GRAPHICS) &&
        virXPathBoolean("count(./graphics) > 0", ctxt) &&
        (!(mig->graphics = qemuMigrationCookieGraphicsXMLParse(ctxt))))
        goto error;

    if ((flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) &&
        virXPathBoolean("count(./lockstate) > 0", ctxt)) {
        mig->lockDriver = virXPathString("string(./lockstate[1]/@driver)", ctxt);
        if (!mig->lockDriver) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing lock driver name in migration cookie"));
            goto error;
        }
        mig->lockState = virXPathString("string(./lockstate[1]/leases[1])", ctxt);
        if (mig->lockState && STREQ(mig->lockState, ""))
            VIR_FREE(mig->lockState);
    }

    if ((flags & QEMU_MIGRATION_COOKIE_PERSISTENT) &&
        virXPathBoolean("count(./domain) > 0", ctxt)) {
        if ((n = virXPathNodeSet("./domain", ctxt, &nodes)) > 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Too many domain elements in "
                             "migration cookie: %d"),
                           n);
            goto error;
        }
        mig->persistent = virDomainDefParseNode(caps, doc, nodes[0],
                                                -1, VIR_DOMAIN_XML_INACTIVE);
        if (!mig->persistent) {
            /* virDomainDefParseNode already reported
             * an error for us */
            goto error;
        }
        VIR_FREE(nodes);
    }

    if ((flags & QEMU_MIGRATION_COOKIE_NETWORK) &&
        virXPathBoolean("count(./network) > 0", ctxt) &&
        (!(mig->network = qemuMigrationCookieNetworkXMLParse(ctxt))))
        goto error;

    if (flags & QEMU_MIGRATION_COOKIE_NBD &&
        virXPathBoolean("boolean(./nbd)", ctxt)) {
        char *port;

        if (VIR_ALLOC(mig->nbd) < 0) {
            virReportOOMError();
            goto error;
        }

        port = virXPathString("string(./nbd/@port)", ctxt);
        if (port && virStrToLong_i(port, NULL, 10, &mig->nbd->port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Malformed nbd port '%s'"),
                           port);
            VIR_FREE(port);
            goto error;
        }
        VIR_FREE(port);
    }

    virObjectUnref(caps);
    return 0;

error:
    VIR_FREE(tmp);
    VIR_FREE(nodes);
    virObjectUnref(caps);
    return -1;
}


static int
qemuMigrationCookieXMLParseStr(qemuMigrationCookiePtr mig,
                               virQEMUDriverPtr driver,
                               const char *xml,
                               unsigned int flags)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    VIR_DEBUG("xml=%s", NULLSTR(xml));

    if (!(doc = virXMLParseStringCtxt(xml, _("(qemu_migration_cookie)"), &ctxt)))
        goto cleanup;

    ret = qemuMigrationCookieXMLParse(mig, driver, doc, ctxt, flags);

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


static int
qemuMigrationBakeCookie(qemuMigrationCookiePtr mig,
                        virQEMUDriverPtr driver,
                        virDomainObjPtr dom,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned int flags)
{
    if (!cookieout || !cookieoutlen)
        return 0;

    *cookieoutlen = 0;

    if (flags & QEMU_MIGRATION_COOKIE_GRAPHICS &&
        qemuMigrationCookieAddGraphics(mig, driver, dom) < 0)
        return -1;

    if (flags & QEMU_MIGRATION_COOKIE_LOCKSTATE &&
        qemuMigrationCookieAddLockstate(mig, driver, dom) < 0)
        return -1;

    if (flags & QEMU_MIGRATION_COOKIE_PERSISTENT &&
        qemuMigrationCookieAddPersistent(mig, dom) < 0)
        return -1;

    if (flags & QEMU_MIGRATION_COOKIE_NETWORK &&
        qemuMigrationCookieAddNetwork(mig, driver, dom) < 0) {
        return -1;
    }

    if ((flags & QEMU_MIGRATION_COOKIE_NBD) &&
        qemuMigrationCookieAddNBD(mig, driver, dom) < 0)
        return -1;

    if (!(*cookieout = qemuMigrationCookieXMLFormatStr(driver, mig)))
        return -1;

    *cookieoutlen = strlen(*cookieout) + 1;

    VIR_DEBUG("cookielen=%d cookie=%s", *cookieoutlen, *cookieout);

    return 0;
}


static qemuMigrationCookiePtr
qemuMigrationEatCookie(virQEMUDriverPtr driver,
                       virDomainObjPtr dom,
                       const char *cookiein,
                       int cookieinlen,
                       unsigned int flags)
{
    qemuMigrationCookiePtr mig = NULL;

    /* Parse & validate incoming cookie (if any) */
    if (cookiein && cookieinlen &&
        cookiein[cookieinlen-1] != '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration cookie was not NULL terminated"));
        goto error;
    }

    VIR_DEBUG("cookielen=%d cookie='%s'", cookieinlen, NULLSTR(cookiein));

    if (!(mig = qemuMigrationCookieNew(dom)))
        return NULL;

    if (cookiein && cookieinlen &&
        qemuMigrationCookieXMLParseStr(mig,
                                       driver,
                                       cookiein,
                                       flags) < 0)
        goto error;

    if (mig->flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) {
        if (!mig->lockDriver) {
            if (virLockManagerPluginUsesState(driver->lockManager)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing %s lock state for migration cookie"),
                               virLockManagerPluginGetName(driver->lockManager));
                goto error;
            }
        } else if (STRNEQ(mig->lockDriver,
                          virLockManagerPluginGetName(driver->lockManager))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Source host lock driver %s different from target %s"),
                           mig->lockDriver,
                           virLockManagerPluginGetName(driver->lockManager));
            goto error;
        }
    }

    return mig;

error:
    qemuMigrationCookieFree(mig);
    return NULL;
}

/**
 * qemuMigrationStartNBDServer:
 * @driver: qemu driver
 * @vm: domain
 *
 * Starts NBD server. This is a newer method to copy
 * storage during migration than using 'blk' and 'inc'
 * arguments in 'migrate' monitor command.
 * Error is reported here.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationStartNBDServer(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned short port = 0;
    const char *listenAddr = "0.0.0.0";
    char *diskAlias = NULL;
    size_t i;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        /* skip shared, RO and source-less disks */
        if (disk->shared || disk->readonly || !disk->src)
            continue;

        VIR_FREE(diskAlias);
        if (virAsprintf(&diskAlias, "%s%s",
                        QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
            goto cleanup;

        if (!port &&
            ((virPortAllocatorAcquire(driver->remotePorts, &port) < 0) ||
             (qemuMonitorNBDServerStart(priv->mon, listenAddr, port) < 0))) {
            qemuDomainObjExitMonitor(driver, vm);
            goto cleanup;
        }

        if (qemuMonitorNBDServerAdd(priv->mon, diskAlias, true) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            goto cleanup;
        }
        qemuDomainObjExitMonitor(driver, vm);
    }

    priv->nbdPort = port;
    ret = 0;

cleanup:
    VIR_FREE(diskAlias);
    if ((ret < 0) && port)
        virPortAllocatorRelease(driver->remotePorts, port);
    return ret;
}

/**
 * qemuMigrationDriveMirror:
 * @driver: qemu driver
 * @vm: domain
 * @mig: migration cookie
 * @host: where are we migrating to
 * @speed: how much should the copying be limited
 * @migrate_flags: migrate monitor command flags
 *
 * Run drive-mirror to feed NBD server running on dst and wait
 * till the process switches into another phase where writes go
 * simultaneously to both source and destination. And this switch
 * is what we are waiting for before proceeding with the next
 * disk. On success, update @migrate_flags so we don't tell
 * 'migrate' command to do the very same operation.
 *
 * Returns 0 on success (@migrate_flags updated),
 *        -1 otherwise.
 */
static int
qemuMigrationDriveMirror(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMigrationCookiePtr mig,
                         const char *host,
                         unsigned long speed,
                         unsigned int *migrate_flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int mon_ret;
    int port;
    size_t i, lastGood = 0;
    char *diskAlias = NULL;
    char *nbd_dest = NULL;
    unsigned int mirror_flags = VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT;
    virErrorPtr err = NULL;

    if (!(*migrate_flags & (QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                            QEMU_MONITOR_MIGRATE_NON_SHARED_INC)))
        return 0;

    if (!mig->nbd) {
        /* Destination doesn't support NBD server.
         * Fall back to previous implementation. */
        VIR_DEBUG("Destination doesn't support NBD server "
                  "Falling back to previous implementation.");
        return 0;
    }

    /* steal NBD port and thus prevent its propagation back to destination */
    port = mig->nbd->port;
    mig->nbd->port = 0;

    if (*migrate_flags & QEMU_MONITOR_MIGRATE_NON_SHARED_INC)
        mirror_flags |= VIR_DOMAIN_BLOCK_REBASE_SHALLOW;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        virDomainBlockJobInfo info;

        /* skip shared, RO and source-less disks */
        if (disk->shared || disk->readonly || !disk->src)
            continue;

        VIR_FREE(diskAlias);
        VIR_FREE(nbd_dest);
        if ((virAsprintf(&diskAlias, "%s%s",
                         QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0) ||
            (virAsprintf(&nbd_dest, "nbd:%s:%d:exportname=%s",
                         host, port, diskAlias) < 0)) {
            virReportOOMError();
            goto error;
        }

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto error;
        mon_ret = qemuMonitorDriveMirror(priv->mon, diskAlias, nbd_dest,
                                         NULL, speed, mirror_flags);
        qemuDomainObjExitMonitor(driver, vm);

        if (mon_ret < 0)
            goto error;

        lastGood = i;

        /* wait for completion */
        while (true) {
            /* Poll every 500ms for progress & to allow cancellation */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 500 * 1000 * 1000ull };

            memset(&info, 0, sizeof(info));

            if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                               QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
                goto error;
            if (priv->job.asyncAbort) {
                /* explicitly do this *after* we entered the monitor,
                 * as this is a critical section so we are guaranteed
                 * priv->job.asyncAbort will not change */
                qemuDomainObjExitMonitor(driver, vm);
                virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                               qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                               _("canceled by client"));
                goto error;
            }
            mon_ret = qemuMonitorBlockJob(priv->mon, diskAlias, NULL, 0,
                                          &info, BLOCK_JOB_INFO, true);
            qemuDomainObjExitMonitor(driver, vm);

            if (mon_ret < 0)
                goto error;

            if (info.cur == info.end) {
                VIR_DEBUG("Drive mirroring of '%s' completed", diskAlias);
                break;
            }

            /* XXX Frankly speaking, we should listen to the events,
             * instead of doing this. But this works for now and we
             * are doing something similar in migration itself anyway */

            virObjectUnlock(vm);

            nanosleep(&ts, NULL);

            virObjectLock(vm);
        }
    }

    /* Okay, copied. Modify migrate_flags */
    *migrate_flags &= ~(QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                        QEMU_MONITOR_MIGRATE_NON_SHARED_INC);
    ret = 0;

cleanup:
    VIR_FREE(diskAlias);
    VIR_FREE(nbd_dest);
    return ret;

error:
    /* don't overwrite any errors */
    err = virSaveLastError();
    /* cancel any outstanding jobs */
    while (lastGood) {
        virDomainDiskDefPtr disk = vm->def->disks[--lastGood];

        /* skip shared, RO disks */
        if (disk->shared || disk->readonly || !disk->src)
            continue;

        VIR_FREE(diskAlias);
        if (virAsprintf(&diskAlias, "%s%s",
                        QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0) {
            virReportOOMError();
            continue;
        }
        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
            if (qemuMonitorBlockJob(priv->mon, diskAlias, NULL, 0,
                                    NULL, BLOCK_JOB_ABORT, true) < 0) {
                VIR_WARN("Unable to cancel block-job on '%s'", diskAlias);
            }
            qemuDomainObjExitMonitor(driver, vm);
        } else {
            VIR_WARN("Unable to enter monitor. No block job cancelled");
        }
    }
    if (err)
        virSetError(err);
    virFreeError(err);
    goto cleanup;
}


static void
qemuMigrationStopNBDServer(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuMigrationCookiePtr mig)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!mig->nbd)
        return;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        return;

    if (qemuMonitorNBDServerStop(priv->mon) < 0)
        VIR_WARN("Unable to stop NBD server");

    qemuDomainObjExitMonitor(driver, vm);

    virPortAllocatorRelease(driver->remotePorts, priv->nbdPort);
    priv->nbdPort = 0;
}

static void
qemuMigrationCancelDriveMirror(qemuMigrationCookiePtr mig,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    char *diskAlias = NULL;

    VIR_DEBUG("mig=%p nbdPort=%d", mig->nbd, priv->nbdPort);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        /* skip shared, RO and source-less disks */
        if (disk->shared || disk->readonly || !disk->src)
            continue;

        VIR_FREE(diskAlias);
        if (virAsprintf(&diskAlias, "%s%s",
                        QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;

        if (qemuMonitorBlockJob(priv->mon, diskAlias, NULL, 0,
                                NULL, BLOCK_JOB_ABORT, true) < 0)
            VIR_WARN("Unable to stop block job on %s", diskAlias);
        qemuDomainObjExitMonitor(driver, vm);
    }

cleanup:
    VIR_FREE(diskAlias);
    return;
}

/* Validate whether the domain is safe to migrate.  If vm is NULL,
 * then this is being run in the v2 Prepare stage on the destination
 * (where we only have the target xml); if vm is provided, then this
 * is being run in either v2 Perform or v3 Begin (where we also have
 * access to all of the domain's metadata, such as whether it is
 * marked autodestroy or has snapshots).  While it would be nice to
 * assume that checking on source is sufficient to prevent ever
 * talking to the destination in the first place, we are stuck with
 * the fact that older servers did not do checks on the source. */
bool
qemuMigrationIsAllowed(virQEMUDriverPtr driver, virDomainObjPtr vm,
                       virDomainDefPtr def, bool remote)
{
    int nsnapshots;
    bool forbid;
    int i;

    if (vm) {
        if (qemuProcessAutoDestroyActive(driver, vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is marked for auto destroy"));
            return false;
        }

        /* perform these checks only when migrating to remote hosts */
        if (remote) {
            nsnapshots = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0);
            if (nsnapshots < 0)
                return false;

            if (nsnapshots > 0) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("cannot migrate domain with %d snapshots"),
                               nsnapshots);
                return false;
            }
        }

        if (virDomainHasDiskMirror(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has an active block job"));
            return false;
        }

        def = vm->def;
    }

    /* Migration with USB host devices is allowed, all other devices are
     * forbidden.
     */
    forbid = false;
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            forbid = true;
            break;
        }
    }
    if (forbid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has assigned non-USB host devices"));
        return false;
    }

    return true;
}

static bool
qemuMigrationIsSafe(virDomainDefPtr def)
{
    int i;

    for (i = 0 ; i < def->ndisks ; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        /* Our code elsewhere guarantees shared disks are either readonly (in
         * which case cache mode doesn't matter) or used with cache=none */
        if (disk->src &&
            !disk->shared &&
            !disk->readonly &&
            disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
            int cfs;

            if (disk->type == VIR_DOMAIN_DISK_TYPE_FILE) {
                if ((cfs = virStorageFileIsClusterFS(disk->src)) == 1)
                    continue;
                else if (cfs < 0)
                    return false;
            } else if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                       disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_RBD) {
                continue;
            }

            virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                           _("Migration may lead to data corruption if disks"
                             " use cache != none"));
            return false;
        }
    }

    return true;
}

/** qemuMigrationSetOffline
 * Pause domain for non-live migration.
 */
int
qemuMigrationSetOffline(virQEMUDriverPtr driver,
                        virDomainObjPtr vm)
{
    int ret;
    VIR_DEBUG("driver=%p vm=%p", driver, vm);
    ret = qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_MIGRATION,
                              QEMU_ASYNC_JOB_MIGRATION_OUT);
    if (ret == 0) {
        virDomainEventPtr event;

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        if (event)
            qemuDomainEventQueue(driver, event);
    }

    return ret;
}


static int
qemuMigrationSetCompression(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            enum qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, job) < 0)
        return -1;

    ret = qemuMonitorGetMigrationCapability(
                priv->mon,
                QEMU_MONITOR_MIGRATION_CAPS_XBZRLE);

    if (ret < 0) {
        goto cleanup;
    } else if (ret == 0) {
        if (job == QEMU_ASYNC_JOB_MIGRATION_IN) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("Compressed migration is not supported by "
                             "target QEMU binary"));
        } else {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("Compressed migration is not supported by "
                             "source QEMU binary"));
        }
        ret = -1;
        goto cleanup;
    }

    ret = qemuMonitorSetMigrationCapability(
                priv->mon,
                QEMU_MONITOR_MIGRATION_CAPS_XBZRLE);

cleanup:
    qemuDomainObjExitMonitor(driver, vm);
    return ret;
}


static int
qemuMigrationUpdateJobStatus(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             const char *job,
                             enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;
    bool wait_for_spice = false;
    bool spice_migrated = false;
    qemuMonitorMigrationStatus status;

    memset(&status, 0, sizeof(status));

    /* If guest uses SPICE and supports seamles_migration we have to hold up
     * migration finish until SPICE server transfers its data */
    if (vm->def->ngraphics == 1 &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SEAMLESS_MIGRATION))
        wait_for_spice = true;

    ret = qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob);
    if (ret < 0) {
        /* Guest already exited; nothing further to update.  */
        return -1;
    }
    ret = qemuMonitorGetMigrationStatus(priv->mon, &status);

    /* If qemu says migrated, check spice */
    if (wait_for_spice &&
        ret == 0 &&
        status.status == QEMU_MONITOR_MIGRATION_STATUS_COMPLETED)
        ret = qemuMonitorGetSpiceMigrationStatus(priv->mon,
                                                 &spice_migrated);

    qemuDomainObjExitMonitor(driver, vm);

    priv->job.status = status;

    if (ret < 0 || virTimeMillisNow(&priv->job.info.timeElapsed) < 0) {
        priv->job.info.type = VIR_DOMAIN_JOB_FAILED;
        return -1;
    }
    priv->job.info.timeElapsed -= priv->job.start;

    ret = -1;
    switch (priv->job.status.status) {
    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
        priv->job.info.type = VIR_DOMAIN_JOB_NONE;
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("%s: %s"), job, _("is not active"));
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
        priv->job.info.fileTotal = priv->job.status.disk_total;
        priv->job.info.fileRemaining = priv->job.status.disk_remaining;
        priv->job.info.fileProcessed = priv->job.status.disk_transferred;

        priv->job.info.memTotal = priv->job.status.ram_total;
        priv->job.info.memRemaining = priv->job.status.ram_remaining;
        priv->job.info.memProcessed = priv->job.status.ram_transferred;

        priv->job.info.dataTotal =
            priv->job.status.ram_total + priv->job.status.disk_total;
        priv->job.info.dataRemaining =
            priv->job.status.ram_remaining + priv->job.status.disk_remaining;
        priv->job.info.dataProcessed =
            priv->job.status.ram_transferred +
            priv->job.status.disk_transferred;

        ret = 0;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
        if ((wait_for_spice && spice_migrated) || (!wait_for_spice))
            priv->job.info.type = VIR_DOMAIN_JOB_COMPLETED;
        ret = 0;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
        priv->job.info.type = VIR_DOMAIN_JOB_FAILED;
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("%s: %s"), job, _("unexpectedly failed"));
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
        priv->job.info.type = VIR_DOMAIN_JOB_CANCELLED;
        virReportError(VIR_ERR_OPERATION_ABORTED,
                       _("%s: %s"), job, _("canceled by client"));
        break;
    }

    return ret;
}


static int
qemuMigrationWaitForCompletion(virQEMUDriverPtr driver, virDomainObjPtr vm,
                               enum qemuDomainAsyncJob asyncJob,
                               virConnectPtr dconn)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *job;

    switch (priv->job.asyncJob) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
        job = _("migration job");
        break;
    case QEMU_ASYNC_JOB_SAVE:
        job = _("domain save job");
        break;
    case QEMU_ASYNC_JOB_DUMP:
        job = _("domain core dump job");
        break;
    default:
        job = _("job");
    }

    priv->job.info.type = VIR_DOMAIN_JOB_UNBOUNDED;

    while (priv->job.info.type == VIR_DOMAIN_JOB_UNBOUNDED) {
        /* Poll every 50ms for progress & to allow cancellation */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000ull };

        if (qemuMigrationUpdateJobStatus(driver, vm, job, asyncJob) < 0)
            goto cleanup;

        if (dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            goto cleanup;
        }

        virObjectUnlock(vm);

        nanosleep(&ts, NULL);

        virObjectLock(vm);
    }

cleanup:
    if (priv->job.info.type == VIR_DOMAIN_JOB_COMPLETED)
        return 0;
    else
        return -1;
}


static int
qemuDomainMigrateGraphicsRelocate(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuMigrationCookiePtr cookie)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (!cookie)
        return 0;

    if (!cookie->graphics)
        return 0;

    /* QEMU doesn't support VNC relocation yet, so
     * skip it to avoid generating an error
     */
    if (cookie->graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
        return 0;

    ret = qemuDomainObjEnterMonitorAsync(driver, vm,
                                         QEMU_ASYNC_JOB_MIGRATION_OUT);
    if (ret == 0) {
        ret = qemuMonitorGraphicsRelocate(priv->mon,
                                          cookie->graphics->type,
                                          cookie->remoteHostname,
                                          cookie->graphics->port,
                                          cookie->graphics->tlsPort,
                                          cookie->graphics->tlsSubject);
        qemuDomainObjExitMonitor(driver, vm);
    }

    return ret;
}


static int
qemuDomainMigrateOPDRelocate(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                             virDomainObjPtr vm,
                             qemuMigrationCookiePtr cookie)
{
    virDomainNetDefPtr netptr;
    int ret = -1;
    int i;

    for (i = 0; i < cookie->network->nnets; i++) {
        netptr = vm->def->nets[i];

        switch (cookie->network->net[i].vporttype) {
        case VIR_NETDEV_VPORT_PROFILE_NONE:
        case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        case VIR_NETDEV_VPORT_PROFILE_8021QBH:
           break;
        case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
            if (virNetDevOpenvswitchSetMigrateData(cookie->network->net[i].portdata,
                                                   netptr->ifname) != 0) {
                virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                                     _("Unable to run command to set OVS port data for "
                                     "interface %s"), netptr->ifname);
                goto cleanup;
            }
            break;
        default:
            break;
        }
    }

    ret = 0;
cleanup:
    return ret;
}


/* This is called for outgoing non-p2p migrations when a connection to the
 * client which initiated the migration was closed but we were waiting for it
 * to follow up with the next phase, that is, in between
 * qemuDomainMigrateBegin3 and qemuDomainMigratePerform3 or
 * qemuDomainMigratePerform3 and qemuDomainMigrateConfirm3.
 */
virDomainObjPtr
qemuMigrationCleanup(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     virConnectPtr conn)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("vm=%s, conn=%p, asyncJob=%s, phase=%s",
              vm->def->name, conn,
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              qemuDomainAsyncJobPhaseToString(priv->job.asyncJob,
                                              priv->job.phase));

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        goto cleanup;

    VIR_DEBUG("The connection which started outgoing migration of domain %s"
              " was closed; canceling the migration",
              vm->def->name);

    switch ((enum qemuMigrationJobPhase) priv->job.phase) {
    case QEMU_MIGRATION_PHASE_BEGIN3:
        /* just forget we were about to migrate */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        VIR_WARN("Migration of domain %s finished but we don't know if the"
                 " domain was successfully started on destination or not",
                 vm->def->name);
        /* clear the job and let higher levels decide what to do */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3:
        /* cannot be seen without an active migration API; unreachable */
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
        /* all done; unreachable */
    case QEMU_MIGRATION_PHASE_PREPARE:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
        /* incoming migration; unreachable */
    case QEMU_MIGRATION_PHASE_PERFORM2:
        /* single phase outgoing migration; unreachable */
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_LAST:
        /* unreachable */
        ;
    }

cleanup:
    return vm;
}

/* The caller is supposed to lock the vm and start a migration job. */
char *qemuMigrationBegin(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         const char *xmlin,
                         const char *dname,
                         char **cookieout,
                         int *cookieoutlen,
                         unsigned long flags)
{
    char *rv = NULL;
    qemuMigrationCookiePtr mig = NULL;
    virDomainDefPtr def = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    unsigned int cookieFlags = QEMU_MIGRATION_COOKIE_LOCKSTATE;

    VIR_DEBUG("driver=%p, vm=%p, xmlin=%s, dname=%s,"
              " cookieout=%p, cookieoutlen=%p, flags=%lx",
              driver, vm, NULLSTR(xmlin), NULLSTR(dname),
              cookieout, cookieoutlen, flags);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Only set the phase if we are inside QEMU_ASYNC_JOB_MIGRATION_OUT.
     * Otherwise we will start the async job later in the perform phase losing
     * change protection.
     */
    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT)
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_BEGIN3);

    if (!qemuMigrationIsAllowed(driver, vm, NULL, true))
        goto cleanup;

    if (!(flags & VIR_MIGRATE_UNSAFE) && !qemuMigrationIsSafe(vm->def))
        goto cleanup;

    if (flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_SERVER)) {
        /* TODO support NBD for TUNNELLED migration */
        if (flags & VIR_MIGRATE_TUNNELLED)
            VIR_DEBUG("NBD in tunnelled migration is currently not supported");
        else {
            cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
            priv->nbdPort = 0;
        }
    }

    if (!(mig = qemuMigrationEatCookie(driver, vm, NULL, 0, 0)))
        goto cleanup;

    if (qemuMigrationBakeCookie(mig, driver, vm,
                                cookieout, cookieoutlen,
                                cookieFlags) < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
    }

    if (xmlin) {
        if (!(def = virDomainDefParseString(caps, xmlin,
                                            QEMU_EXPECTED_VIRT_TYPES,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        if (STRNEQ(def->name, vm->def->name)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("target domain name doesn't match source name"));
            goto cleanup;
        }

        if (!virDomainDefCheckABIStability(vm->def, def))
            goto cleanup;

        rv = qemuDomainDefFormatLive(driver, def, false, true);
    } else {
        rv = qemuDomainDefFormatLive(driver, vm->def, false, true);
    }

cleanup:
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    virDomainDefFree(def);
    return rv;
}


/* Prepare is the first step, and it runs on the destination host.
 */

static void
qemuMigrationPrepareCleanup(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("driver=%p, vm=%s, job=%s, asyncJob=%s",
              driver,
              vm->def->name,
              qemuDomainJobTypeToString(priv->job.active),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN))
        return;
    qemuDomainObjDiscardAsyncJob(driver, vm);
}

static int
qemuMigrationPrepareAny(virQEMUDriverPtr driver,
                        virConnectPtr dconn,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        const char *dname,
                        const char *dom_xml,
                        const char *migrateFrom,
                        virStreamPtr st,
                        unsigned long flags)
{
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int dataFD[2] = { -1, -1 };
    qemuDomainObjPrivatePtr priv = NULL;
    unsigned long long now;
    qemuMigrationCookiePtr mig = NULL;
    bool tunnel = !!st;
    char *origname = NULL;
    char *xmlout = NULL;
    unsigned int cookieFlags;
    virCapsPtr caps = NULL;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (tunnel) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(caps, dom_xml,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (!qemuMigrationIsAllowed(driver, NULL, def, true))
        goto cleanup;

    /* Target domain name, maybe renamed. */
    if (dname) {
        origname = def->name;
        def->name = strdup(dname);
        if (def->name == NULL)
            goto cleanup;
    }

    /* Let migration hook filter domain XML */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml;
        int hookret;

        if (!(xml = qemuDomainDefFormatXML(driver, def,
                                           VIR_DOMAIN_XML_SECURE |
                                           VIR_DOMAIN_XML_MIGRATABLE)))
            goto cleanup;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, def->name,
                              VIR_HOOK_QEMU_OP_MIGRATE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, &xmlout);
        VIR_FREE(xml);

        if (hookret < 0) {
            goto cleanup;
        } else if (hookret == 0) {
            if (!*xmlout) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                virDomainDefPtr newdef;

                VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);
                newdef = virDomainDefParseString(caps, xmlout,
                                                 QEMU_EXPECTED_VIRT_TYPES,
                                                 VIR_DOMAIN_XML_INACTIVE);
                if (!newdef)
                    goto cleanup;

                if (!virDomainDefCheckABIStability(def, newdef)) {
                    virDomainDefFree(newdef);
                    goto cleanup;
                }

                virDomainDefFree(def);
                def = newdef;
            }
        }
    }

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   caps,
                                   def,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    def = NULL;
    priv = vm->privateData;
    priv->origname = origname;
    origname = NULL;

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                       QEMU_MIGRATION_COOKIE_LOCKSTATE |
                                       QEMU_MIGRATION_COOKIE_NBD)))
        goto cleanup;

    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto cleanup;
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PREPARE);

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    if (tunnel &&
        (pipe(dataFD) < 0 || virSetCloseExec(dataFD[1]) < 0)) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto endjob;
    }

    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming $migrateFrom
     */
    if (qemuProcessStart(dconn, driver, vm, migrateFrom, dataFD[0], NULL, NULL,
                         VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
                         VIR_QEMU_PROCESS_START_PAUSED |
                         VIR_QEMU_PROCESS_START_AUTODESROY) < 0) {
        virDomainAuditStart(vm, "migrated", false);
        /* Note that we don't set an error here because qemuProcessStart
         * should have already done that.
         */
        goto endjob;
    }

    if (tunnel) {
        if (virFDStreamOpen(st, dataFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot pass pipe for tunnelled migration"));
            goto stop;
        }
        dataFD[1] = -1; /* 'st' owns the FD now & will close it */
    }

    if (flags & VIR_MIGRATE_COMPRESSED &&
        qemuMigrationSetCompression(driver, vm,
                                    QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto stop;

    if (mig->lockState) {
        VIR_DEBUG("Received lockstate %s", mig->lockState);
        VIR_FREE(priv->lockState);
        priv->lockState = mig->lockState;
        mig->lockState = NULL;
    } else {
        VIR_DEBUG("Received no lockstate");
    }

done:
    if (flags & VIR_MIGRATE_OFFLINE)
        cookieFlags = 0;
    else
        cookieFlags = QEMU_MIGRATION_COOKIE_GRAPHICS;

    if (mig->nbd &&
        flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_SERVER)) {
        /* TODO support NBD for TUNNELLED migration */
        if (flags & VIR_MIGRATE_TUNNELLED)
            VIR_DEBUG("NBD in tunnelled migration is currently not supported");
        else {
            if (qemuMigrationStartNBDServer(driver, vm) < 0) {
                /* error already reported */
                goto endjob;
            }
            cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
        }
    }

    if (qemuMigrationBakeCookie(mig, driver, vm, cookieout,
                                cookieoutlen, cookieFlags) < 0) {
        /* We could tear down the whole guest here, but
         * cookie data is (so far) non-critical, so that
         * seems a little harsh. We'll just warn for now.
         */
        VIR_WARN("Unable to encode migration cookie");
    }

    if (qemuDomainCleanupAdd(vm, qemuMigrationPrepareCleanup) < 0)
        goto endjob;

    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        virDomainAuditStart(vm, "migrated", true);
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    }

    /* We keep the job active across API calls until the finish() call.
     * This prevents any other APIs being invoked while incoming
     * migration is taking place.
     */
    if (!qemuMigrationJobContinue(vm)) {
        vm = NULL;
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("domain disappeared"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(origname);
    VIR_FREE(xmlout);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(dataFD[0]);
    VIR_FORCE_CLOSE(dataFD[1]);
    if (vm) {
        if (ret >= 0 || vm->persistent)
            virObjectUnlock(vm);
        else
            qemuDomainRemoveInactive(driver, vm);
        if (ret < 0 && priv->nbdPort) {
            virPortAllocatorRelease(driver->remotePorts, priv->nbdPort);
            priv->nbdPort = 0;
        }
    }
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    return ret;

stop:
    virDomainAuditStart(vm, "migrated", false);
    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, 0);

endjob:
    if (!qemuMigrationJobFinish(driver, vm)) {
        vm = NULL;
    }
    goto cleanup;
}


/*
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
int
qemuMigrationPrepareTunnel(virQEMUDriverPtr driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           virStreamPtr st,
                           const char *dname,
                           const char *dom_xml,
                           unsigned long flags)
{
    int ret;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, st=%p, dname=%s, dom_xml=%s "
              "flags=%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, st, NULLSTR(dname), dom_xml, flags);

    /* QEMU will be started with -incoming stdio (which qemu_command might
     * convert to exec:cat or fd:n)
     */
    ret = qemuMigrationPrepareAny(driver, dconn, cookiein, cookieinlen,
                                  cookieout, cookieoutlen, dname, dom_xml,
                                  "stdio", st, flags);
    return ret;
}


int
qemuMigrationPrepareDirect(virQEMUDriverPtr driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           const char *uri_in,
                           char **uri_out,
                           const char *dname,
                           const char *dom_xml,
                           unsigned long flags)
{
    static int port = 0;
    int this_port;
    char *hostname = NULL;
    char migrateFrom [64];
    const char *p;
    int ret = -1;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_in=%s, uri_out=%p, "
              "dname=%s, dom_xml=%s flags=%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, NULLSTR(uri_in), uri_out,
              NULLSTR(dname), dom_xml, flags);

    /* The URI passed in may be NULL or a string "tcp://somehostname:port".
     *
     * If the URI passed in is NULL then we allocate a port number
     * from our pool of port numbers and return a URI of
     * "tcp://ourhostname:port".
     *
     * If the URI passed in is not NULL then we try to parse out the
     * port number and use that (note that the hostname is assumed
     * to be a correct hostname which refers to the target machine).
     */
    if (uri_in == NULL) {
        this_port = QEMUD_MIGRATION_FIRST_PORT + port++;
        if (port == QEMUD_MIGRATION_NUM_PORTS) port = 0;

        /* Get hostname */
        if ((hostname = virGetHostname(NULL)) == NULL)
            goto cleanup;

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatibility with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        /* Caller frees */
        if (virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STRPREFIX(uri_in, "tcp:")) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("only tcp URIs are supported for KVM/QEMU"
                             " migrations"));
            goto cleanup;
        }

        /* Get the port number. */
        p = strrchr(uri_in, ':');
        if (p == strchr(uri_in, ':')) {
            /* Generate a port */
            this_port = QEMUD_MIGRATION_FIRST_PORT + port++;
            if (port == QEMUD_MIGRATION_NUM_PORTS)
                port = 0;

            /* Caller frees */
            if (virAsprintf(uri_out, "%s:%d", uri_in, this_port) < 0) {
                virReportOOMError();
                goto cleanup;
            }

        } else {
            p++; /* definitely has a ':' in it, see above */
            this_port = virParseNumber(&p);
            if (this_port == -1 || p-uri_in != strlen(uri_in)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               "%s", _("URI ended with incorrect ':port'"));
                goto cleanup;
            }
        }
    }

    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    /* QEMU will be started with -incoming tcp:0.0.0.0:port */
    snprintf(migrateFrom, sizeof(migrateFrom), "tcp:0.0.0.0:%d", this_port);

    ret = qemuMigrationPrepareAny(driver, dconn, cookiein, cookieinlen,
                                  cookieout, cookieoutlen, dname, dom_xml,
                                  migrateFrom, NULL, flags);
cleanup:
    VIR_FREE(hostname);
    if (ret != 0)
        VIR_FREE(*uri_out);
    return ret;
}


enum qemuMigrationDestinationType {
    MIGRATION_DEST_HOST,
    MIGRATION_DEST_CONNECT_HOST,
    MIGRATION_DEST_UNIX,
    MIGRATION_DEST_FD,
};

enum qemuMigrationForwardType {
    MIGRATION_FWD_DIRECT,
    MIGRATION_FWD_STREAM,
};

typedef struct _qemuMigrationSpec qemuMigrationSpec;
typedef qemuMigrationSpec *qemuMigrationSpecPtr;
struct _qemuMigrationSpec {
    enum qemuMigrationDestinationType destType;
    union {
        struct {
            const char *name;
            int port;
        } host;

        struct {
            char *file;
            int sock;
        } unix_socket;

        struct {
            int qemu;
            int local;
        } fd;
    } dest;

    enum qemuMigrationForwardType fwdType;
    union {
        virStreamPtr stream;
    } fwd;
};

#define TUNNEL_SEND_BUF_SIZE 65536

typedef struct _qemuMigrationIOThread qemuMigrationIOThread;
typedef qemuMigrationIOThread *qemuMigrationIOThreadPtr;
struct _qemuMigrationIOThread {
    virThread thread;
    virStreamPtr st;
    int sock;
    virError err;
    int wakeupRecvFD;
    int wakeupSendFD;
};

static void qemuMigrationIOFunc(void *arg)
{
    qemuMigrationIOThreadPtr data = arg;
    char *buffer = NULL;
    struct pollfd fds[2];
    int timeout = -1;
    virErrorPtr err = NULL;

    VIR_DEBUG("Running migration tunnel; stream=%p, sock=%d",
              data->st, data->sock);

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0) {
        virReportOOMError();
        goto abrt;
    }

    fds[0].fd = data->sock;
    fds[1].fd = data->wakeupRecvFD;

    for (;;) {
        int ret;

        fds[0].events = fds[1].events = POLLIN;
        fds[0].revents = fds[1].revents = 0;

        ret = poll(fds, ARRAY_CARDINALITY(fds), timeout);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("poll failed in migration tunnel"));
            goto abrt;
        }

        if (ret == 0) {
            /* We were asked to gracefully stop but reading would block. This
             * can only happen if qemu told us migration finished but didn't
             * close the migration fd. We handle this in the same way as EOF.
             */
            VIR_DEBUG("QEMU forgot to close migration fd");
            break;
        }

        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            char stop = 0;

            if (saferead(data->wakeupRecvFD, &stop, 1) != 1) {
                virReportSystemError(errno, "%s",
                                     _("failed to read from wakeup fd"));
                goto abrt;
            }

            VIR_DEBUG("Migration tunnel was asked to %s",
                      stop ? "abort" : "finish");
            if (stop) {
                goto abrt;
            } else {
                timeout = 0;
            }
        }

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            int nbytes;

            nbytes = saferead(data->sock, buffer, TUNNEL_SEND_BUF_SIZE);
            if (nbytes > 0) {
                if (virStreamSend(data->st, buffer, nbytes) < 0)
                    goto error;
            } else if (nbytes < 0) {
                virReportSystemError(errno, "%s",
                        _("tunnelled migration failed to read from qemu"));
                goto abrt;
            } else {
                /* EOF; get out of here */
                break;
            }
        }
    }

    if (virStreamFinish(data->st) < 0)
        goto error;

    VIR_FREE(buffer);

    return;

abrt:
    err = virSaveLastError();
    if (err && err->code == VIR_ERR_OK) {
        virFreeError(err);
        err = NULL;
    }
    virStreamAbort(data->st);
    if (err) {
        virSetError(err);
        virFreeError(err);
    }

error:
    virCopyLastError(&data->err);
    virResetLastError();
    VIR_FREE(buffer);
}


static qemuMigrationIOThreadPtr
qemuMigrationStartTunnel(virStreamPtr st,
                         int sock)
{
    qemuMigrationIOThreadPtr io = NULL;
    int wakeupFD[2] = { -1, -1 };

    if (pipe2(wakeupFD, O_CLOEXEC) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to make pipe"));
        goto error;
    }

    if (VIR_ALLOC(io) < 0)
        goto no_memory;

    io->st = st;
    io->sock = sock;
    io->wakeupRecvFD = wakeupFD[0];
    io->wakeupSendFD = wakeupFD[1];

    if (virThreadCreate(&io->thread, true,
                        qemuMigrationIOFunc,
                        io) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create migration thread"));
        goto error;
    }

    return io;

no_memory:
    virReportOOMError();
error:
    VIR_FORCE_CLOSE(wakeupFD[0]);
    VIR_FORCE_CLOSE(wakeupFD[1]);
    VIR_FREE(io);
    return NULL;
}

static int
qemuMigrationStopTunnel(qemuMigrationIOThreadPtr io, bool error)
{
    int rv = -1;
    char stop = error ? 1 : 0;

    /* make sure the thread finishes its job and is joinable */
    if (safewrite(io->wakeupSendFD, &stop, 1) != 1) {
        virReportSystemError(errno, "%s",
                             _("failed to wakeup migration tunnel"));
        goto cleanup;
    }

    virThreadJoin(&io->thread);

    /* Forward error from the IO thread, to this thread */
    if (io->err.code != VIR_ERR_OK) {
        if (error)
            rv = 0;
        else
            virSetError(&io->err);
        virResetError(&io->err);
        goto cleanup;
    }

    rv = 0;

cleanup:
    VIR_FORCE_CLOSE(io->wakeupSendFD);
    VIR_FORCE_CLOSE(io->wakeupRecvFD);
    VIR_FREE(io);
    return rv;
}

static int
qemuMigrationConnect(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     qemuMigrationSpecPtr spec)
{
    virNetSocketPtr sock;
    const char *host;
    char *port = NULL;
    int ret = -1;

    host = spec->dest.host.name;
    if (virAsprintf(&port, "%d", spec->dest.host.port) < 0) {
        virReportOOMError();
        return -1;
    }

    spec->destType = MIGRATION_DEST_FD;
    spec->dest.fd.qemu = -1;

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;
    if (virNetSocketNewConnectTCP(host, port, &sock) == 0) {
        spec->dest.fd.qemu = virNetSocketDupFD(sock, true);
        virObjectUnref(sock);
    }
    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0 ||
        spec->dest.fd.qemu == -1)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(port);
    if (ret < 0)
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
    return ret;
}

static int
qemuMigrationRun(virQEMUDriverPtr driver,
                 virDomainObjPtr vm,
                 const char *cookiein,
                 int cookieinlen,
                 char **cookieout,
                 int *cookieoutlen,
                 unsigned long flags,
                 unsigned long resource,
                 qemuMigrationSpecPtr spec,
                 virConnectPtr dconn)
{
    int ret = -1;
    unsigned int migrate_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationCookiePtr mig = NULL;
    qemuMigrationIOThreadPtr iothread = NULL;
    int fd = -1;
    unsigned long migrate_speed = resource ? resource : priv->migMaxBandwidth;
    virErrorPtr orig_err = NULL;
    unsigned int cookieFlags = 0;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu, "
              "spec=%p (dest=%d, fwd=%d)",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              spec, spec->destType, spec->fwdType);

    if (flags & VIR_MIGRATE_NON_SHARED_DISK) {
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_INC) {
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (virLockManagerPluginUsesState(driver->lockManager) &&
        !cookieout) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Migration with lock driver %s requires"
                         " cookie support"),
                       virLockManagerPluginGetName(driver->lockManager));
        return -1;
    }

    mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                 cookieFlags | QEMU_MIGRATION_COOKIE_GRAPHICS);
    if (!mig)
        goto cleanup;

    if (qemuDomainMigrateGraphicsRelocate(driver, vm, mig) < 0)
        VIR_WARN("unable to provide data for graphics client relocation");

    /* this will update migrate_flags on success */
    if (qemuMigrationDriveMirror(driver, vm, mig, spec->dest.host.name,
                                 migrate_speed, &migrate_flags) < 0) {
        /* error reported by helper func */
        goto cleanup;
    }

    /* Before EnterMonitor, since qemuMigrationSetOffline already does that */
    if (!(flags & VIR_MIGRATE_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuMigrationSetOffline(driver, vm) < 0)
            goto cleanup;
    }

    if (flags & VIR_MIGRATE_COMPRESSED &&
        qemuMigrationSetCompression(driver, vm,
                                    QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (priv->job.asyncAbort) {
        /* explicitly do this *after* we entered the monitor,
         * as this is a critical section so we are guaranteed
         * priv->job.asyncAbort will not change */
        qemuDomainObjExitMonitor(driver, vm);
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                       qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                       _("canceled by client"));
        goto cleanup;
    }

    if (qemuMonitorSetMigrationSpeed(priv->mon, migrate_speed) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }

    /* connect to the destination qemu if needed */
    if (spec->destType == MIGRATION_DEST_CONNECT_HOST &&
        qemuMigrationConnect(driver, vm, spec) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }

    switch (spec->destType) {
    case MIGRATION_DEST_HOST:
        ret = qemuMonitorMigrateToHost(priv->mon, migrate_flags,
                                       spec->dest.host.name,
                                       spec->dest.host.port);
        break;

    case MIGRATION_DEST_CONNECT_HOST:
        /* handled above and transformed into MIGRATION_DEST_FD */
        break;

    case MIGRATION_DEST_UNIX:
        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_UNIX)) {
            ret = qemuMonitorMigrateToUnix(priv->mon, migrate_flags,
                                           spec->dest.unix_socket.file);
        } else {
            const char *args[] = {
                "nc", "-U", spec->dest.unix_socket.file, NULL
            };
            ret = qemuMonitorMigrateToCommand(priv->mon, migrate_flags, args);
        }
        break;

    case MIGRATION_DEST_FD:
        if (spec->fwdType != MIGRATION_FWD_DIRECT) {
            fd = spec->dest.fd.local;
            spec->dest.fd.local = -1;
        }
        ret = qemuMonitorMigrateToFd(priv->mon, migrate_flags,
                                     spec->dest.fd.qemu);
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
        break;
    }
    qemuDomainObjExitMonitor(driver, vm);
    if (ret < 0)
        goto cleanup;
    ret = -1;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */

    if (spec->destType == MIGRATION_DEST_UNIX) {
        /* It is also possible that the migrate didn't fail initially, but
         * rather failed later on.  Check its status before waiting for a
         * connection from qemu which may never be initiated.
         */
        if (qemuMigrationUpdateJobStatus(driver, vm, _("migration job"),
                                         QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cancel;

        while ((fd = accept(spec->dest.unix_socket.sock, NULL, NULL)) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("failed to accept connection from qemu"));
            goto cancel;
        }
    }

    if (spec->fwdType != MIGRATION_FWD_DIRECT &&
        !(iothread = qemuMigrationStartTunnel(spec->fwd.stream, fd)))
        goto cancel;

    if (qemuMigrationWaitForCompletion(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT,
                                       dconn) < 0)
        goto cleanup;

    /* When migration completed, QEMU will have paused the
     * CPUs for us, but unless we're using the JSON monitor
     * we won't have been notified of this, so might still
     * think we're running. For v2 protocol this doesn't
     * matter because we'll kill the VM soon, but for v3
     * this is important because we stay paused until the
     * confirm3 step, but need to release the lock state
     */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuMigrationSetOffline(driver, vm) < 0)
            goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret < 0 && !orig_err)
        orig_err = virSaveLastError();

    /* cancel any outstanding NBD jobs */
    qemuMigrationCancelDriveMirror(mig, driver, vm);

    if (spec->fwdType != MIGRATION_FWD_DIRECT) {
        if (iothread && qemuMigrationStopTunnel(iothread, ret < 0) < 0)
            ret = -1;
        VIR_FORCE_CLOSE(fd);
    }

    cookieFlags |= (QEMU_MIGRATION_COOKIE_PERSISTENT |
                    QEMU_MIGRATION_COOKIE_NETWORK);
    if (ret == 0 &&
        qemuMigrationBakeCookie(mig, driver, vm, cookieout,
                                cookieoutlen, cookieFlags) < 0) {
        VIR_WARN("Unable to encode migration cookie");
    }

    qemuMigrationCookieFree(mig);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    return ret;

cancel:
    orig_err = virSaveLastError();

    if (virDomainObjIsActive(vm)) {
        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
            qemuMonitorMigrateCancel(priv->mon);
            qemuDomainObjExitMonitor(driver, vm);
        }
    }
    goto cleanup;
}

/* Perform migration using QEMU's native TCP migrate support,
 * not encrypted obviously
 */
static int doNativeMigrate(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           const char *uri,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned long flags,
                           unsigned long resource,
                           virConnectPtr dconn)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virURIPtr uribits = NULL;
    int ret = -1;
    qemuMigrationSpec spec;

    VIR_DEBUG("driver=%p, vm=%p, uri=%s, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu",
              driver, vm, uri, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource);

    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri, "tcp://")) {
        char *tmp;
        /* HACK: source host generates bogus URIs, so fix them up */
        if (virAsprintf(&tmp, "tcp://%s", uri + strlen("tcp:")) < 0) {
            virReportOOMError();
            return -1;
        }
        uribits = virURIParse(tmp);
        VIR_FREE(tmp);
    } else {
        uribits = virURIParse(uri);
    }
    if (!uribits)
        return -1;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD))
        spec.destType = MIGRATION_DEST_CONNECT_HOST;
    else
        spec.destType = MIGRATION_DEST_HOST;
    spec.dest.host.name = uribits->server;
    spec.dest.host.port = uribits->port;
    spec.fwdType = MIGRATION_FWD_DIRECT;

    ret = qemuMigrationRun(driver, vm, cookiein, cookieinlen, cookieout,
                           cookieoutlen, flags, resource, &spec, dconn);

    if (spec.destType == MIGRATION_DEST_FD)
        VIR_FORCE_CLOSE(spec.dest.fd.qemu);

    virURIFree(uribits);

    return ret;
}


static int doTunnelMigrate(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virStreamPtr st,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned long flags,
                           unsigned long resource,
                           virConnectPtr dconn)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virNetSocketPtr sock = NULL;
    int ret = -1;
    qemuMigrationSpec spec;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    VIR_DEBUG("driver=%p, vm=%p, st=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu",
              driver, vm, st, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource);

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD) &&
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_UNIX) &&
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_EXEC)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Source qemu is too old to support tunnelled migration"));
        virObjectUnref(cfg);
        return -1;
    }

    spec.fwdType = MIGRATION_FWD_STREAM;
    spec.fwd.stream = st;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD)) {
        int fds[2];

        spec.destType = MIGRATION_DEST_FD;
        spec.dest.fd.qemu = -1;
        spec.dest.fd.local = -1;

        if (pipe2(fds, O_CLOEXEC) == 0) {
            spec.dest.fd.qemu = fds[1];
            spec.dest.fd.local = fds[0];
        }
        if (spec.dest.fd.qemu == -1 ||
            virSecurityManagerSetImageFDLabel(driver->securityManager, vm->def,
                                              spec.dest.fd.qemu) < 0) {
            virReportSystemError(errno, "%s",
                        _("cannot create pipe for tunnelled migration"));
            goto cleanup;
        }
    } else {
        spec.destType = MIGRATION_DEST_UNIX;
        spec.dest.unix_socket.sock = -1;
        spec.dest.unix_socket.file = NULL;

        if (virAsprintf(&spec.dest.unix_socket.file,
                        "%s/qemu.tunnelmigrate.src.%s",
                        cfg->libDir, vm->def->name) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virNetSocketNewListenUNIX(spec.dest.unix_socket.file, 0700,
                                      cfg->user, cfg->group,
                                      &sock) < 0 ||
            virNetSocketListen(sock, 1) < 0)
            goto cleanup;

        spec.dest.unix_socket.sock = virNetSocketGetFD(sock);
    }

    ret = qemuMigrationRun(driver, vm, cookiein, cookieinlen, cookieout,
                           cookieoutlen, flags, resource, &spec, dconn);

cleanup:
    if (spec.destType == MIGRATION_DEST_FD) {
        VIR_FORCE_CLOSE(spec.dest.fd.qemu);
        VIR_FORCE_CLOSE(spec.dest.fd.local);
    } else {
        virObjectUnref(sock);
        VIR_FREE(spec.dest.unix_socket.file);
    }

    virObjectUnref(cfg);
    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion2
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int doPeer2PeerMigrate2(virQEMUDriverPtr driver,
                               virConnectPtr sconn ATTRIBUTE_UNUSED,
                               virConnectPtr dconn,
                               virDomainObjPtr vm,
                               const char *dconnuri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret;
    virErrorPtr orig_err = NULL;
    int cancelled;
    virStreamPtr st = NULL;
    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, vm=%p, dconnuri=%s, "
              "flags=%lx, dname=%s, resource=%lu",
              driver, sconn, dconn, vm, NULLSTR(dconnuri),
              flags, NULLSTR(dname), resource);

    /* In version 2 of the protocol, the prepare step is slightly
     * different.  We fetch the domain XML of the source domain
     * and pass it to Prepare2.
     */
    if (!(dom_xml = qemuDomainFormatXML(driver, vm,
                                        QEMU_DOMAIN_FORMAT_LIVE_FLAGS |
                                        VIR_DOMAIN_XML_MIGRATABLE)))
        return -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    VIR_DEBUG("Prepare2 %p", dconn);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        /*
         * Tunnelled Migrate Version 2 does not support cookies
         * due to missing parameters in the prepareTunnel() API.
         */

        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepareTunnel
            (dconn, st, flags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    } else {
        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepare2
            (dconn, &cookie, &cookielen, NULL, &uri_out,
             flags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemote, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_TUNNELLED) &&
        (uri_out == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare2 did not set uri"));
        cancelled = 1;
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", sconn);
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(driver, vm, st,
                              NULL, 0, NULL, NULL,
                              flags, resource, dconn);
    else
        ret = doNativeMigrate(driver, vm, uri_out,
                              cookie, cookielen,
                              NULL, NULL, /* No out cookie with v2 migration */
                              flags, resource, dconn);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : vm->def->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    qemuDomainObjEnterRemote(vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen,
         uri_out ? uri_out : dconnuri, flags, cancelled);
    qemuDomainObjExitRemote(vm);

cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookie);

    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion3
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int doPeer2PeerMigrate3(virQEMUDriverPtr driver,
                               virConnectPtr sconn,
                               virConnectPtr dconn,
                               virDomainObjPtr vm,
                               const char *xmlin,
                               const char *dconnuri,
                               const char *uri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    char *dom_xml = NULL;
    int cookieinlen = 0;
    int cookieoutlen = 0;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    int cancelled;
    virStreamPtr st = NULL;
    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, vm=%p, xmlin=%s, "
              "dconnuri=%s, uri=%s, flags=%lx, dname=%s, resource=%lu",
              driver, sconn, dconn, vm, NULLSTR(xmlin),
              NULLSTR(dconnuri), NULLSTR(uri), flags,
              NULLSTR(dname), resource);

    /* Unlike the virDomainMigrateVersion3 counterpart, we don't need
     * to worry about auto-setting the VIR_MIGRATE_CHANGE_PROTECTION
     * bit here, because we are already running inside the context of
     * a single job.  */

    dom_xml = qemuMigrationBegin(driver, vm, xmlin, dname,
                                 &cookieout, &cookieoutlen, flags);
    if (!dom_xml)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    VIR_DEBUG("Prepare3 %p", dconn);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED) {
        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepareTunnel3
            (dconn, st, cookiein, cookieinlen,
             &cookieout, &cookieoutlen,
             flags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    } else {
        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepare3
            (dconn, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             uri, &uri_out, flags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE) {
        VIR_DEBUG("Offline migration, skipping Perform phase");
        VIR_FREE(cookieout);
        cookieoutlen = 0;
        cancelled = 0;
        goto finish;
    }

    if (!(flags & VIR_MIGRATE_TUNNELLED) &&
        (uri_out == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare3 did not set uri"));
        cancelled = 1;
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s uri_out=%s", sconn, uri, uri_out);
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(driver, vm, st,
                              cookiein, cookieinlen,
                              &cookieout, &cookieoutlen,
                              flags, resource, dconn);
    else
        ret = doNativeMigrate(driver, vm, uri_out,
                              cookiein, cookieinlen,
                              &cookieout, &cookieoutlen,
                              flags, resource, dconn);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0) {
        orig_err = virSaveLastError();
    } else {
        qemuMigrationJobSetPhase(driver, vm,
                                 QEMU_MIGRATION_PHASE_PERFORM3_DONE);
    }

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

finish:
    /*
     * The status code from the source is passed to the destination.
     * The dest can cleanup in the source indicated it failed to
     * send all migration data. Returns NULL for ddomain if
     * the dest was unable to complete migration.
     */
    VIR_DEBUG("Finish3 %p ret=%d", dconn, ret);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    dname = dname ? dname : vm->def->name;
    qemuDomainObjEnterRemote(vm);
    ddomain = dconn->driver->domainMigrateFinish3
        (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
         dconnuri, uri_out ? uri_out : uri, flags, cancelled);
    qemuDomainObjExitRemote(vm);

    /* If ddomain is NULL, then we were unable to start
     * the guest on the target, and must restart on the
     * source. There is a small chance that the ddomain
     * is NULL due to an RPC failure, in which case
     * ddomain could in fact be running on the dest.
     * The lock manager plugins should take care of
     * safety in this scenario.
     */
    cancelled = ddomain == NULL ? 1 : 0;

    /* If finish3 set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        orig_err = virSaveLastError();

    /*
     * If cancelled, then src VM will be restarted, else
     * it will be killed
     */
    VIR_DEBUG("Confirm3 %p cancelled=%d vm=%p", sconn, cancelled, vm);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    ret = qemuMigrationConfirm(driver, sconn, vm,
                               cookiein, cookieinlen,
                               flags, cancelled);
    /* If Confirm3 returns -1, there's nothing more we can
     * do, but fortunately worst case is that there is a
     * domain left in 'paused' state on source.
     */
    if (ret < 0)
        VIR_WARN("Guest %s probably left in 'paused' state on source",
                 vm->def->name);

 cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);

    return ret;
}


static int doPeer2PeerMigrate(virQEMUDriverPtr driver,
                              virConnectPtr sconn,
                              virDomainObjPtr vm,
                              const char *xmlin,
                              const char *dconnuri,
                              const char *uri,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource,
                              bool *v3proto)
{
    int ret = -1;
    virConnectPtr dconn = NULL;
    bool p2p;
    virErrorPtr orig_err = NULL;
    bool offline = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    VIR_DEBUG("driver=%p, sconn=%p, vm=%p, xmlin=%s, dconnuri=%s, "
              "uri=%s, flags=%lx, dname=%s, resource=%lu",
              driver, sconn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), flags, NULLSTR(dname), resource);

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    qemuDomainObjEnterRemote(vm);
    dconn = virConnectOpen(dconnuri);
    qemuDomainObjExitRemote(vm);
    if (dconn == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to connect to remote libvirt URI %s"), dconnuri);
        virObjectUnref(cfg);
        return -1;
    }

    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    qemuDomainObjEnterRemote(vm);
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
        /* v3proto reflects whether the caller used Perform3, but with
         * p2p migrate, regardless of whether Perform2 or Perform3
         * were used, we decide protocol based on what target supports
         */
    *v3proto = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                        VIR_DRV_FEATURE_MIGRATION_V3);
    if (flags & VIR_MIGRATE_OFFLINE)
        offline = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                           VIR_DRV_FEATURE_MIGRATION_OFFLINE);
    qemuDomainObjExitRemote(vm);

    if (!p2p) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_OFFLINE && !offline) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("offline migration is not supported by "
                         "the destination host"));
        goto cleanup;
    }

    /* domain may have been stopped while we were talking to remote daemon */
    if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    /* Change protection is only required on the source side (us), and
     * only for v3 migration when begin and perform are separate jobs.
     * But peer-2-peer is already a single job, and we still want to
     * talk to older destinations that would reject the flag.
     * Therefore it is safe to clear the bit here.  */
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    if (*v3proto)
        ret = doPeer2PeerMigrate3(driver, sconn, dconn, vm, xmlin,
                                  dconnuri, uri, flags, dname, resource);
    else
        ret = doPeer2PeerMigrate2(driver, sconn, dconn, vm,
                                  dconnuri, flags, dname, resource);

cleanup:
    orig_err = virSaveLastError();
    qemuDomainObjEnterRemote(vm);
    virConnectClose(dconn);
    qemuDomainObjExitRemote(vm);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(cfg);
    return ret;
}


/*
 * This implements perform part of the migration protocol when migration job
 * does not need to be active across several APIs, i.e., peer2peer migration or
 * perform phase of v2 non-peer2peer migration.
 */
static int
qemuMigrationPerformJob(virQEMUDriverPtr driver,
                        virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *xmlin,
                        const char *dconnuri,
                        const char *uri,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned long flags,
                        const char *dname,
                        unsigned long resource,
                        bool v3proto)
{
    virDomainEventPtr event = NULL;
    int ret = -1;
    int resume = 0;
    virErrorPtr orig_err = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!qemuMigrationIsAllowed(driver, vm, NULL, true))
        goto endjob;

    if (!(flags & VIR_MIGRATE_UNSAFE) && !qemuMigrationIsSafe(vm->def))
        goto endjob;

    resume = virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING;

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        ret = doPeer2PeerMigrate(driver, conn, vm, xmlin,
                                 dconnuri, uri, flags, dname,
                                 resource, &v3proto);
    } else {
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
        ret = doNativeMigrate(driver, vm, uri, cookiein, cookieinlen,
                              cookieout, cookieoutlen,
                              flags, resource, NULL);
    }
    if (ret < 0)
        goto endjob;

    /*
     * In v3 protocol, the source VM is not killed off until the
     * confirm step.
     */
    if (!v3proto) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    }
    resume = 0;

endjob:
    if (ret < 0)
        orig_err = virSaveLastError();

    if (resume && virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        /* we got here through some sort of failure; start the domain again */
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure"),
                      vm->def->name);
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }

    if (!qemuMigrationJobFinish(driver, vm)) {
        vm = NULL;
    } else if (!virDomainObjIsActive(vm) &&
               (!vm->persistent ||
                (ret == 0 && (flags & VIR_MIGRATE_UNDEFINE_SOURCE)))) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE)
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

/*
 * This implements perform phase of v3 migration protocol.
 */
static int
qemuMigrationPerformPhase(virQEMUDriverPtr driver,
                          virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *uri,
                          const char *cookiein,
                          int cookieinlen,
                          char **cookieout,
                          int *cookieoutlen,
                          unsigned long flags,
                          unsigned long resource)
{
    virDomainEventPtr event = NULL;
    int ret = -1;
    bool resume;
    bool hasrefs;

    /* If we didn't start the job in the begin phase, start it now. */
    if (!(flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;
    } else if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT)) {
        goto cleanup;
    }

    qemuMigrationJobStartPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    virQEMUCloseCallbacksUnset(driver->closeCallbacks, vm,
                               qemuMigrationCleanup);

    resume = virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING;
    ret = doNativeMigrate(driver, vm, uri, cookiein, cookieinlen,
                          cookieout, cookieoutlen,
                          flags, resource, NULL);

    if (ret < 0 && resume &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        /* we got here through some sort of failure; start the domain again */
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best
             */
            VIR_ERROR(_("Failed to resume guest %s after failure"),
                      vm->def->name);
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }

    if (ret < 0)
        goto endjob;

    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3_DONE);

    if (virQEMUCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                                 qemuMigrationCleanup) < 0)
        goto endjob;

endjob:
    if (ret < 0)
        hasrefs = qemuMigrationJobFinish(driver, vm);
    else
        hasrefs = qemuMigrationJobContinue(vm);
    if (!hasrefs) {
        vm = NULL;
    } else if (!virDomainObjIsActive(vm) && !vm->persistent) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
}

int
qemuMigrationPerform(virQEMUDriverPtr driver,
                     virConnectPtr conn,
                     virDomainObjPtr vm,
                     const char *xmlin,
                     const char *dconnuri,
                     const char *uri,
                     const char *cookiein,
                     int cookieinlen,
                     char **cookieout,
                     int *cookieoutlen,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource,
                     bool v3proto)
{
    VIR_DEBUG("driver=%p, conn=%p, vm=%p, xmlin=%s, dconnuri=%s, "
              "uri=%s, cookiein=%s, cookieinlen=%d, cookieout=%p, "
              "cookieoutlen=%p, flags=%lx, dname=%s, resource=%lu, v3proto=%d",
              driver, conn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, NULLSTR(dname),
              resource, v3proto);

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (cookieinlen) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("received unexpected cookie with P2P migration"));
            return -1;
        }

        return qemuMigrationPerformJob(driver, conn, vm, xmlin, dconnuri, uri,
                                       cookiein, cookieinlen, cookieout,
                                       cookieoutlen, flags, dname, resource,
                                       v3proto);
    } else {
        if (dconnuri) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Unexpected dconnuri parameter with non-peer2peer migration"));
            return -1;
        }

        if (v3proto) {
            return qemuMigrationPerformPhase(driver, conn, vm, uri,
                                             cookiein, cookieinlen,
                                             cookieout, cookieoutlen,
                                             flags, resource);
        } else {
            return qemuMigrationPerformJob(driver, conn, vm, xmlin, dconnuri,
                                           uri, cookiein, cookieinlen,
                                           cookieout, cookieoutlen, flags,
                                           dname, resource, v3proto);
        }
    }
}

static int
qemuMigrationVPAssociatePortProfiles(virDomainDefPtr def) {
    int i;
    int last_good_net = -1;
    virDomainNetDefPtr net;

    for (i = 0; i < def->nnets; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            if (virNetDevVPortProfileAssociate(net->ifname,
                                               virDomainNetGetActualVirtPortProfile(net),
                                               &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               -1,
                                               def->uuid,
                                               VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH,
                                               false) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Port profile Associate failed for %s"),
                               net->ifname);
                goto err_exit;
            }
            VIR_DEBUG("Port profile Associate succeeded for %s", net->ifname);

            if (virNetDevMacVLanVPortProfileRegisterCallback(net->ifname, &net->mac,
                                                             virDomainNetGetActualDirectDev(net), def->uuid,
                                                             virDomainNetGetActualVirtPortProfile(net),
                                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE))
                goto err_exit;
        }
        last_good_net = i;
    }

    return 0;

err_exit:
    for (i = 0; i < last_good_net; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            ignore_value(virNetDevVPortProfileDisassociate(net->ifname,
                                                           virDomainNetGetActualVirtPortProfile(net),
                                                           &net->mac,
                                                           virDomainNetGetActualDirectDev(net),
                                                           -1,
                                                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH));
        }
    }
    return -1;
}


virDomainPtr
qemuMigrationFinish(virQEMUDriverPtr driver,
                    virConnectPtr dconn,
                    virDomainObjPtr vm,
                    const char *cookiein,
                    int cookieinlen,
                    char **cookieout,
                    int *cookieoutlen,
                    unsigned long flags,
                    int retcode,
                    bool v3proto)
{
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int newVM = 1;
    qemuMigrationCookiePtr mig = NULL;
    virErrorPtr orig_err = NULL;
    int cookie_flags = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virCapsPtr caps = NULL;

    VIR_DEBUG("driver=%p, dconn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, retcode=%d",
              driver, dconn, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, retcode);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN))
        goto cleanup;

    qemuMigrationJobStartPhase(driver, vm,
                               v3proto ? QEMU_MIGRATION_PHASE_FINISH3
                                       : QEMU_MIGRATION_PHASE_FINISH2);

    qemuDomainCleanupRemove(vm, qemuMigrationPrepareCleanup);

    cookie_flags = QEMU_MIGRATION_COOKIE_NETWORK;
    if (flags & VIR_MIGRATE_PERSIST_DEST)
        cookie_flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein,
                                       cookieinlen, cookie_flags)))
        goto endjob;

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit"));
            goto endjob;
        }

        if (!(flags & VIR_MIGRATE_OFFLINE)) {
            if (qemuMigrationVPAssociatePortProfiles(vm->def) < 0) {
                qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                                VIR_QEMU_PROCESS_STOP_MIGRATED);
                virDomainAuditStop(vm, "failed");
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_STOPPED,
                                                 VIR_DOMAIN_EVENT_STOPPED_FAILED);
                goto endjob;
            }
            if (mig->network)
                if (qemuDomainMigrateOPDRelocate(driver, vm, mig) < 0)
                    VIR_WARN("unable to provide network data for relocation");
        }

        qemuMigrationStopNBDServer(driver, vm, mig);

        if (flags & VIR_MIGRATE_PERSIST_DEST) {
            virDomainDefPtr vmdef;
            if (vm->persistent)
                newVM = 0;
            vm->persistent = 1;
            if (mig->persistent)
                vm->newDef = vmdef = mig->persistent;
            else
                vmdef = virDomainObjGetPersistentDef(caps, vm);
            if (!vmdef || virDomainSaveConfig(cfg->configDir, vmdef) < 0) {
                /* Hmpf.  Migration was successful, but making it persistent
                 * was not.  If we report successful, then when this domain
                 * shuts down, management tools are in for a surprise.  On the
                 * other hand, if we report failure, then the management tools
                 * might try to restart the domain on the source side, even
                 * though the domain is actually running on the destination.
                 * Return a NULL dom pointer, and hope that this is a rare
                 * situation and management tools are smart.
                 */

                /*
                 * However, in v3 protocol, the source VM is still available
                 * to restart during confirm() step, so we kill it off now.
                 */
                if (v3proto) {
                    if (!(flags & VIR_MIGRATE_OFFLINE)) {
                        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                                        VIR_QEMU_PROCESS_STOP_MIGRATED);
                        virDomainAuditStop(vm, "failed");
                    }
                    if (newVM)
                        vm->persistent = 0;
                }
                if (!vmdef)
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("can't get vmdef"));
                goto endjob;
            }

            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_DEFINED,
                                             newVM ?
                                             VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                             VIR_DOMAIN_EVENT_DEFINED_UPDATED);
            if (event)
                qemuDomainEventQueue(driver, event);
            event = NULL;
        }

        if (!(flags & VIR_MIGRATE_PAUSED) && !(flags & VIR_MIGRATE_OFFLINE)) {
            /* run 'cont' on the destination, which allows migration on qemu
             * >= 0.10.6 to work properly.  This isn't strictly necessary on
             * older qemu's, but it also doesn't hurt anything there
             */
            if (qemuProcessStartCPUs(driver, vm, dconn,
                                     VIR_DOMAIN_RUNNING_MIGRATED,
                                     QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
                if (virGetLastError() == NULL)
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("resume operation failed"));
                /* Need to save the current error, in case shutting
                 * down the process overwrites it
                 */
                orig_err = virSaveLastError();

                /*
                 * In v3 protocol, the source VM is still available to
                 * restart during confirm() step, so we kill it off
                 * now.
                 * In v2 protocol, the source is dead, so we leave
                 * target in paused state, in case admin can fix
                 * things up
                 */
                if (v3proto) {
                    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                                    VIR_QEMU_PROCESS_STOP_MIGRATED);
                    virDomainAuditStop(vm, "failed");
                    event = virDomainEventNewFromObj(vm,
                                                     VIR_DOMAIN_EVENT_STOPPED,
                                                     VIR_DOMAIN_EVENT_STOPPED_FAILED);
                }
                goto endjob;
            }
        }

        dom = virGetDomain(dconn, vm->def->name, vm->def->uuid);

        if (!(flags & VIR_MIGRATE_OFFLINE)) {
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_RESUMED,
                                             VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
                virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                     VIR_DOMAIN_PAUSED_USER);
                if (event)
                    qemuDomainEventQueue(driver, event);
                event = virDomainEventNewFromObj(vm,
                                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                                 VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
            }
        }

        if (virDomainObjIsActive(vm) &&
            virDomainSaveStatus(caps, cfg->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto endjob;
        }

        /* Guest is successfully running, so cancel previous auto destroy */
        qemuProcessAutoDestroyRemove(driver, vm);
    } else if (!(flags & VIR_MIGRATE_OFFLINE)) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "failed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
    }

    if (qemuMigrationBakeCookie(mig, driver, vm, cookieout, cookieoutlen, 0) < 0)
        VIR_WARN("Unable to encode migration cookie");

endjob:
    if (qemuMigrationJobFinish(driver, vm) == 0) {
        vm = NULL;
    } else if (!vm->persistent && !virDomainObjIsActive(vm)) {
        qemuDomainRemoveInactive(driver, vm);
        vm = NULL;
    }

cleanup:
    if (vm) {
        VIR_FREE(priv->origname);
        virObjectUnlock(vm);
    }
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuMigrationCookieFree(mig);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}


int qemuMigrationConfirm(virQEMUDriverPtr driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned int flags,
                         int retcode)
{
    qemuMigrationCookiePtr mig;
    virDomainEventPtr event = NULL;
    int rv = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virCapsPtr caps = NULL;

    VIR_DEBUG("driver=%p, conn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "flags=%x, retcode=%d",
              driver, conn, vm, NULLSTR(cookiein), cookieinlen,
              flags, retcode);

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    qemuMigrationJobSetPhase(driver, vm,
                             retcode == 0
                             ? QEMU_MIGRATION_PHASE_CONFIRM3
                             : QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED);

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen, 0)))
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    /* Did the migration go as planned?  If yes, kill off the
     * domain object, but if no, resume CPUs
     */
    if (retcode == 0) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    } else {

        /* cancel any outstanding NBD jobs */
        qemuMigrationCancelDriveMirror(mig, driver, vm);

        /* run 'cont' on the destination, which allows migration on qemu
         * >= 0.10.6 to work properly.  This isn't strictly necessary on
         * older qemu's, but it also doesn't hurt anything there
         */
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_MIGRATED,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0) {
            if (virGetLastError() == NULL)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("resume operation failed"));
            goto cleanup;
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        if (virDomainSaveStatus(caps, cfg->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto cleanup;
        }
    }

done:
    qemuMigrationCookieFree(mig);
    rv = 0;

cleanup:
    if (event)
        qemuDomainEventQueue(driver, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return rv;
}


/* Helper function called while vm is active.  */
int
qemuMigrationToFile(virQEMUDriverPtr driver, virDomainObjPtr vm,
                    int fd, off_t offset, const char *path,
                    const char *compressor,
                    bool bypassSecurityDriver,
                    enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rc;
    bool restoreLabel = false;
    virCommandPtr cmd = NULL;
    int pipeFD[2] = { -1, -1 };
    unsigned long saveMigBandwidth = priv->migMaxBandwidth;
    char *errbuf = NULL;

    /* Increase migration bandwidth to unlimited since target is a file.
     * Failure to change migration speed is not fatal. */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        qemuMonitorSetMigrationSpeed(priv->mon,
                                     QEMU_DOMAIN_MIG_BANDWIDTH_MAX);
        priv->migMaxBandwidth = QEMU_DOMAIN_MIG_BANDWIDTH_MAX;
        qemuDomainObjExitMonitor(driver, vm);
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD) &&
        (!compressor || pipe(pipeFD) == 0)) {
        /* All right! We can use fd migration, which means that qemu
         * doesn't have to open() the file, so while we still have to
         * grant SELinux access, we can do it on fd and avoid cleanup
         * later, as well as skip futzing with cgroup.  */
        if (virSecurityManagerSetImageFDLabel(driver->securityManager, vm->def,
                                              compressor ? pipeFD[1] : fd) < 0)
            goto cleanup;
        bypassSecurityDriver = true;
    } else {
        /* Phooey - we have to fall back on exec migration, where qemu
         * has to popen() the file by name, and block devices have to be
         * given cgroup ACL permission.  We might also stumble on
         * a race present in some qemu versions where it does a wait()
         * that botches pclose.  */
        if (qemuCgroupControllerActive(driver,
                                       VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name,
                                   &cgroup, 0) != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to find cgroup for %s"),
                               vm->def->name);
                goto cleanup;
            }
            rc = virCgroupAllowDevicePath(cgroup, path,
                                          VIR_CGROUP_DEVICE_RW);
            virDomainAuditCgroupPath(vm, cgroup, "allow", path, "rw", rc);
            if (rc == 1) {
                /* path was not a device, no further need for cgroup */
                virCgroupFree(&cgroup);
            } else if (rc < 0) {
                virReportSystemError(-rc,
                                     _("Unable to allow device %s for %s"),
                                     path, vm->def->name);
                goto cleanup;
            }
        }
        if ((!bypassSecurityDriver) &&
            virSecurityManagerSetSavedStateLabel(driver->securityManager,
                                                 vm->def, path) < 0)
            goto cleanup;
        restoreLabel = true;
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (!compressor) {
        const char *args[] = { "cat", NULL };

        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD) &&
            priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
            rc = qemuMonitorMigrateToFd(priv->mon,
                                        QEMU_MONITOR_MIGRATE_BACKGROUND,
                                        fd);
        } else {
            rc = qemuMonitorMigrateToFile(priv->mon,
                                          QEMU_MONITOR_MIGRATE_BACKGROUND,
                                          args, path, offset);
        }
    } else {
        const char *prog = compressor;
        const char *args[] = {
            prog,
            "-c",
            NULL
        };
        if (pipeFD[0] != -1) {
            cmd = virCommandNewArgs(args);
            virCommandSetInputFD(cmd, pipeFD[0]);
            virCommandSetOutputFD(cmd, &fd);
            virCommandSetErrorBuffer(cmd, &errbuf);
            virCommandDoAsyncIO(cmd);
            if (virSetCloseExec(pipeFD[1]) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to set cloexec flag"));
                qemuDomainObjExitMonitor(driver, vm);
                goto cleanup;
            }
            if (virCommandRunAsync(cmd, NULL) < 0) {
                qemuDomainObjExitMonitor(driver, vm);
                goto cleanup;
            }
            rc = qemuMonitorMigrateToFd(priv->mon,
                                        QEMU_MONITOR_MIGRATE_BACKGROUND,
                                        pipeFD[1]);
            if (VIR_CLOSE(pipeFD[0]) < 0 ||
                VIR_CLOSE(pipeFD[1]) < 0)
                VIR_WARN("failed to close intermediate pipe");
        } else {
            rc = qemuMonitorMigrateToFile(priv->mon,
                                          QEMU_MONITOR_MIGRATE_BACKGROUND,
                                          args, path, offset);
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

    if (rc < 0)
        goto cleanup;

    rc = qemuMigrationWaitForCompletion(driver, vm, asyncJob, NULL);

    if (rc < 0)
        goto cleanup;

    if (cmd && virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    /* Restore max migration bandwidth */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        qemuMonitorSetMigrationSpeed(priv->mon, saveMigBandwidth);
        priv->migMaxBandwidth = saveMigBandwidth;
        qemuDomainObjExitMonitor(driver, vm);
    }

    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    if (cmd) {
        VIR_DEBUG("Compression binary stderr: %s", NULLSTR(errbuf));
        VIR_FREE(errbuf);
        virCommandFree(cmd);
    }
    if (restoreLabel && (!bypassSecurityDriver) &&
        virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm->def, path) < 0)
        VIR_WARN("failed to restore save state label on %s", path);

    if (cgroup != NULL) {
        rc = virCgroupDenyDevicePath(cgroup, path,
                                     VIR_CGROUP_DEVICE_RWM);
        virDomainAuditCgroupPath(vm, cgroup, "deny", path, "rwm", rc);
        if (rc < 0)
            VIR_WARN("Unable to deny device %s for %s %d",
                     path, vm->def->name, rc);
        virCgroupFree(&cgroup);
    }
    return ret;
}

int
qemuMigrationJobStart(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      enum qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuDomainObjBeginAsyncJob(driver, vm, job) < 0)
        return -1;

    if (job == QEMU_ASYNC_JOB_MIGRATION_IN) {
        qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_NONE);
    } else {
        qemuDomainObjSetAsyncJobMask(vm, DEFAULT_JOB_MASK |
                                     JOB_MASK(QEMU_JOB_SUSPEND) |
                                     JOB_MASK(QEMU_JOB_MIGRATION_OP));
    }

    priv->job.info.type = VIR_DOMAIN_JOB_UNBOUNDED;

    return 0;
}

void
qemuMigrationJobSetPhase(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         enum qemuMigrationJobPhase phase)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (phase < priv->job.phase) {
        VIR_ERROR(_("migration protocol going backwards %s => %s"),
                  qemuMigrationJobPhaseTypeToString(priv->job.phase),
                  qemuMigrationJobPhaseTypeToString(phase));
        return;
    }

    qemuDomainObjSetJobPhase(driver, vm, phase);
}

void
qemuMigrationJobStartPhase(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           enum qemuMigrationJobPhase phase)
{
    virObjectRef(vm);
    qemuMigrationJobSetPhase(driver, vm, phase);
}

bool
qemuMigrationJobContinue(virDomainObjPtr vm)
{
    qemuDomainObjReleaseAsyncJob(vm);
    return virObjectUnref(vm);
}

bool
qemuMigrationJobIsActive(virDomainObjPtr vm,
                         enum qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->job.asyncJob != job) {
        const char *msg;

        if (job == QEMU_ASYNC_JOB_MIGRATION_IN)
            msg = _("domain '%s' is not processing incoming migration");
        else
            msg = _("domain '%s' is not being migrated");

        virReportError(VIR_ERR_OPERATION_INVALID, msg, vm->def->name);
        return false;
    }
    return true;
}

bool
qemuMigrationJobFinish(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    return qemuDomainObjEndAsyncJob(driver, vm);
}
