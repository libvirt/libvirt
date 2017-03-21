/*
 * qemu_migration_cookie.c: QEMU migration cookie handling
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

#ifdef WITH_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#include "locking/domain_lock.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetdevopenvswitch.h"
#include "virstring.h"
#include "virutil.h"

#include "qemu_domain.h"
#include "qemu_migration_cookie.h"


#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration_cookie");

VIR_ENUM_IMPL(qemuMigrationCookieFlag,
              QEMU_MIGRATION_COOKIE_FLAG_LAST,
              "graphics",
              "lockstate",
              "persistent",
              "network",
              "nbd",
              "statistics",
              "memory-hotplug",
              "cpu-hotplug");


static void
qemuMigrationCookieGraphicsFree(qemuMigrationCookieGraphicsPtr grap)
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
    size_t i;

    if (!network)
        return;

    if (network->net) {
        for (i = 0; i < network->nnets; i++)
            VIR_FREE(network->net[i].portdata);
    }
    VIR_FREE(network->net);
    VIR_FREE(network);
}


static void
qemuMigrationCookieNBDFree(qemuMigrationCookieNBDPtr nbd)
{
    if (!nbd)
        return;

    while (nbd->ndisks)
        VIR_FREE(nbd->disks[--nbd->ndisks].target);
    VIR_FREE(nbd->disks);
    VIR_FREE(nbd);
}


void
qemuMigrationCookieFree(qemuMigrationCookiePtr mig)
{
    if (!mig)
        return;

    qemuMigrationCookieGraphicsFree(mig->graphics);
    qemuMigrationCookieNetworkFree(mig->network);
    qemuMigrationCookieNBDFree(mig->nbd);

    VIR_FREE(mig->localHostname);
    VIR_FREE(mig->remoteHostname);
    VIR_FREE(mig->name);
    VIR_FREE(mig->lockState);
    VIR_FREE(mig->lockDriver);
    VIR_FREE(mig->jobInfo);
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
        goto error;

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
        goto error;

    gnutls_x509_crt_get_dn(cert, subject, &subjectlen);
    subject[subjectlen] = '\0';

    VIR_FREE(certfile);
    VIR_FREE(pemdata);

    return subject;

 error:
    VIR_FREE(certfile);
    VIR_FREE(pemdata);
    return NULL;
}
#endif

static qemuMigrationCookieGraphicsPtr
qemuMigrationCookieGraphicsSpiceAlloc(virQEMUDriverPtr driver,
                                      virDomainGraphicsDefPtr def,
                                      virDomainGraphicsListenDefPtr glisten)
{
    qemuMigrationCookieGraphicsPtr mig = NULL;
    const char *listenAddr;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (VIR_ALLOC(mig) < 0)
        goto error;

    mig->type = VIR_DOMAIN_GRAPHICS_TYPE_SPICE;
    mig->port = def->data.spice.port;
    if (cfg->spiceTLS)
        mig->tlsPort = def->data.spice.tlsPort;
    else
        mig->tlsPort = -1;

    if (!glisten || !(listenAddr = glisten->address))
        listenAddr = cfg->spiceListen;

#ifdef WITH_GNUTLS
    if (cfg->spiceTLS &&
        !(mig->tlsSubject = qemuDomainExtractTLSSubject(cfg->spiceTLSx509certdir)))
        goto error;
#endif
    if (VIR_STRDUP(mig->listen, listenAddr) < 0)
        goto error;

    virObjectUnref(cfg);
    return mig;

 error:
    qemuMigrationCookieGraphicsFree(mig);
    virObjectUnref(cfg);
    return NULL;
}


static qemuMigrationCookieNetworkPtr
qemuMigrationCookieNetworkAlloc(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                                virDomainDefPtr def)
{
    qemuMigrationCookieNetworkPtr mig;
    size_t i;

    if (VIR_ALLOC(mig) < 0)
        goto error;

    mig->nnets = def->nnets;

    if (VIR_ALLOC_N(mig->net, def->nnets) <0)
        goto error;

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
                        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        goto error;

    if (priv->origname)
        name = priv->origname;
    else
        name = dom->def->name;
    if (VIR_STRDUP(mig->name, name) < 0)
        goto error;
    memcpy(mig->uuid, dom->def->uuid, VIR_UUID_BUFLEN);

    if (!(mig->localHostname = virGetHostname()))
        goto error;
    if (virGetHostUUID(mig->localHostuuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain host UUID"));
        goto error;
    }

    return mig;

 error:
    qemuMigrationCookieFree(mig);
    return NULL;
}


static int
qemuMigrationCookieAddGraphics(qemuMigrationCookiePtr mig,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr dom)
{
    size_t i = 0;

    if (mig->flags & QEMU_MIGRATION_COOKIE_GRAPHICS) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration graphics data already present"));
        return -1;
    }

    for (i = 0; i < dom->def->ngraphics; i++) {
        if (dom->def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            virDomainGraphicsListenDefPtr glisten =
                virDomainGraphicsGetListen(dom->def->graphics[i], 0);

            if (!glisten) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing listen element"));
                return -1;
            }

            switch (glisten->type) {
            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
                /* Seamless migration is supported only for listen types
                 * 'address and 'network'. */
                if (!(mig->graphics =
                      qemuMigrationCookieGraphicsSpiceAlloc(driver,
                                                            dom->def->graphics[i],
                                                            glisten)))
                    return -1;
                mig->flags |= QEMU_MIGRATION_COOKIE_GRAPHICS;
                break;

            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
                break;
            }

            /* Seamless migration is supported only for one graphics. */
            if (mig->graphics)
                break;
        }
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
        if (VIR_STRDUP(mig->lockState, priv->lockState) < 0)
            return -1;
    } else {
        if (virDomainLockProcessInquire(driver->lockManager, dom, &mig->lockState) < 0)
            return -1;
    }

    if (VIR_STRDUP(mig->lockDriver, virLockManagerPluginGetName(driver->lockManager)) < 0) {
        VIR_FREE(mig->lockState);
        return -1;
    }

    mig->flags |= QEMU_MIGRATION_COOKIE_LOCKSTATE;
    mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_LOCKSTATE;

    return 0;
}


int
qemuMigrationCookieAddPersistent(qemuMigrationCookiePtr mig,
                                 virDomainDefPtr def)
{
    if (mig->flags & QEMU_MIGRATION_COOKIE_PERSISTENT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Migration persistent data already present"));
        return -1;
    }

    if (!def)
        return 0;

    mig->persistent = def;
    mig->flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;
    mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_PERSISTENT;
    return 0;
}


virDomainDefPtr
qemuMigrationCookieGetPersistent(qemuMigrationCookiePtr mig)
{
    virDomainDefPtr def = mig->persistent;

    mig->persistent = NULL;
    mig->flags &= ~QEMU_MIGRATION_COOKIE_PERSISTENT;
    mig->flagsMandatory &= ~QEMU_MIGRATION_COOKIE_PERSISTENT;

    return def;
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
                          virQEMUDriverPtr driver,
                          virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr stats = NULL;
    size_t i;
    int ret = -1, rc;

    /* It is not a bug if there already is a NBD data */
    qemuMigrationCookieNBDFree(mig->nbd);

    if (VIR_ALLOC(mig->nbd) < 0)
        return -1;

    if (vm->def->ndisks &&
        VIR_ALLOC_N(mig->nbd->disks, vm->def->ndisks) < 0)
        return -1;
    mig->nbd->ndisks = 0;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuBlockStats *entry;

        if (!stats) {
            if (!(stats = virHashCreate(10, virHashValueFree)))
                goto cleanup;

            if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                               priv->job.asyncJob) < 0)
                goto cleanup;
            rc = qemuMonitorBlockStatsUpdateCapacity(priv->mon, stats, false);
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            if (rc < 0)
                goto cleanup;
        }

        if (!disk->info.alias ||
            !(entry = virHashLookup(stats, disk->info.alias)))
            continue;

        if (VIR_STRDUP(mig->nbd->disks[mig->nbd->ndisks].target,
                       disk->dst) < 0)
            goto cleanup;
        mig->nbd->disks[mig->nbd->ndisks].capacity = entry->capacity;
        mig->nbd->ndisks++;
    }

    mig->nbd->port = priv->nbdPort;
    mig->flags |= QEMU_MIGRATION_COOKIE_NBD;

    ret = 0;
 cleanup:
    virHashFree(stats);
    return ret;
}


static int
qemuMigrationCookieAddStatistics(qemuMigrationCookiePtr mig,
                                 virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->job.completed)
        return 0;

    if (!mig->jobInfo && VIR_ALLOC(mig->jobInfo) < 0)
        return -1;

    *mig->jobInfo = *priv->job.completed;
    mig->flags |= QEMU_MIGRATION_COOKIE_STATS;

    return 0;
}


static void
qemuMigrationCookieGraphicsXMLFormat(virBufferPtr buf,
                                     qemuMigrationCookieGraphicsPtr grap)
{
    virBufferAsprintf(buf, "<graphics type='%s' port='%d' listen='%s'",
                      virDomainGraphicsTypeToString(grap->type),
                      grap->port, grap->listen);
    if (grap->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
        virBufferAsprintf(buf, " tlsPort='%d'", grap->tlsPort);
    if (grap->tlsSubject) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<cert info='subject' value='%s'/>\n", grap->tlsSubject);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</graphics>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


static void
qemuMigrationCookieNetworkXMLFormat(virBufferPtr buf,
                                    qemuMigrationCookieNetworkPtr optr)
{
    size_t i;
    bool empty = true;

    for (i = 0; i < optr->nnets; i++) {
        /* If optr->net[i].vporttype is not set, there is nothing to transfer */
        if (optr->net[i].vporttype != VIR_NETDEV_VPORT_PROFILE_NONE) {
            if (empty) {
                virBufferAddLit(buf, "<network>\n");
                virBufferAdjustIndent(buf, 2);
                empty = false;
            }
            virBufferAsprintf(buf, "<interface index='%zu' vporttype='%s'",
                              i, virNetDevVPortTypeToString(optr->net[i].vporttype));
            if (optr->net[i].portdata) {
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                virBufferEscapeString(buf, "<portdata>%s</portdata>\n",
                                      optr->net[i].portdata);
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</interface>\n");
            } else {
                virBufferAddLit(buf, "/>\n");
            }
        }
    }
    if (!empty) {
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</network>\n");
    }
}


static void
qemuMigrationCookieStatisticsXMLFormat(virBufferPtr buf,
                                       qemuDomainJobInfoPtr jobInfo)
{
    qemuMonitorMigrationStats *stats = &jobInfo->stats;

    virBufferAddLit(buf, "<statistics>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<started>%llu</started>\n", jobInfo->started);
    virBufferAsprintf(buf, "<stopped>%llu</stopped>\n", jobInfo->stopped);
    virBufferAsprintf(buf, "<sent>%llu</sent>\n", jobInfo->sent);
    if (jobInfo->timeDeltaSet)
        virBufferAsprintf(buf, "<delta>%lld</delta>\n", jobInfo->timeDelta);

    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_TIME_ELAPSED,
                      jobInfo->timeElapsed);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_TIME_REMAINING,
                      jobInfo->timeRemaining);
    if (stats->downtime_set)
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_DOWNTIME,
                          stats->downtime);
    if (stats->setup_time_set)
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_SETUP_TIME,
                          stats->setup_time);

    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_TOTAL,
                      stats->ram_total);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                      stats->ram_transferred);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_REMAINING,
                      stats->ram_remaining);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_BPS,
                      stats->ram_bps);

    if (stats->ram_duplicate_set) {
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_MEMORY_CONSTANT,
                          stats->ram_duplicate);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_MEMORY_NORMAL,
                          stats->ram_normal);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES,
                          stats->ram_normal_bytes);
    }

    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE,
                      stats->ram_dirty_rate);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_MEMORY_ITERATION,
                      stats->ram_iteration);

    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_DISK_TOTAL,
                      stats->disk_total);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_DISK_PROCESSED,
                      stats->disk_transferred);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_DISK_REMAINING,
                      stats->disk_remaining);
    virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                      VIR_DOMAIN_JOB_DISK_BPS,
                      stats->disk_bps);

    if (stats->xbzrle_set) {
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_COMPRESSION_CACHE,
                          stats->xbzrle_cache_size);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_COMPRESSION_BYTES,
                          stats->xbzrle_bytes);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_COMPRESSION_PAGES,
                          stats->xbzrle_pages);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES,
                          stats->xbzrle_cache_miss);
        virBufferAsprintf(buf, "<%1$s>%2$llu</%1$s>\n",
                          VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW,
                          stats->xbzrle_overflow);
    }

    virBufferAsprintf(buf, "<%1$s>%2$d</%1$s>\n",
                      VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE,
                      stats->cpu_throttle_percentage);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</statistics>\n");
}


static int
qemuMigrationCookieXMLFormat(virQEMUDriverPtr driver,
                             virBufferPtr buf,
                             qemuMigrationCookiePtr mig)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char hostuuidstr[VIR_UUID_STRING_BUFLEN];
    size_t i;

    virUUIDFormat(mig->uuid, uuidstr);
    virUUIDFormat(mig->localHostuuid, hostuuidstr);

    virBufferAddLit(buf, "<qemu-migration>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", mig->name);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);
    virBufferEscapeString(buf, "<hostname>%s</hostname>\n", mig->localHostname);
    virBufferAsprintf(buf, "<hostuuid>%s</hostuuid>\n", hostuuidstr);

    for (i = 0; i < QEMU_MIGRATION_COOKIE_FLAG_LAST; i++) {
        if (mig->flagsMandatory & (1 << i))
            virBufferAsprintf(buf, "<feature name='%s'/>\n",
                              qemuMigrationCookieFlagTypeToString(i));
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_GRAPHICS) &&
        mig->graphics)
        qemuMigrationCookieGraphicsXMLFormat(buf, mig->graphics);

    if ((mig->flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) &&
        mig->lockState) {
        virBufferAsprintf(buf, "<lockstate driver='%s'>\n",
                          mig->lockDriver);
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<leases>%s</leases>\n",
                          mig->lockState);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</lockstate>\n");
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_PERSISTENT) &&
        mig->persistent) {
        if (qemuDomainDefFormatBuf(driver,
                                   mig->persistent,
                                   VIR_DOMAIN_XML_INACTIVE |
                                   VIR_DOMAIN_XML_SECURE |
                                   VIR_DOMAIN_XML_MIGRATABLE,
                                   buf) < 0)
            return -1;
    }

    if ((mig->flags & QEMU_MIGRATION_COOKIE_NETWORK) && mig->network)
        qemuMigrationCookieNetworkXMLFormat(buf, mig->network);

    if ((mig->flags & QEMU_MIGRATION_COOKIE_NBD) && mig->nbd) {
        virBufferAddLit(buf, "<nbd");
        if (mig->nbd->port)
            virBufferAsprintf(buf, " port='%d'", mig->nbd->port);
        if (mig->nbd->ndisks) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            for (i = 0; i < mig->nbd->ndisks; i++) {
                virBufferEscapeString(buf, "<disk target='%s'",
                                      mig->nbd->disks[i].target);
                virBufferAsprintf(buf, " capacity='%llu'/>\n",
                                  mig->nbd->disks[i].capacity);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</nbd>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    if (mig->flags & QEMU_MIGRATION_COOKIE_STATS && mig->jobInfo)
        qemuMigrationCookieStatisticsXMLFormat(buf, mig->jobInfo);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</qemu-migration>\n");
    return 0;
}


static char *
qemuMigrationCookieXMLFormatStr(virQEMUDriverPtr driver,
                                qemuMigrationCookiePtr mig)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (qemuMigrationCookieXMLFormat(driver, &buf, mig) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


static qemuMigrationCookieGraphicsPtr
qemuMigrationCookieGraphicsXMLParse(xmlXPathContextPtr ctxt)
{
    qemuMigrationCookieGraphicsPtr grap;
    char *tmp;

    if (VIR_ALLOC(grap) < 0)
        goto error;

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

 error:
    qemuMigrationCookieGraphicsFree(grap);
    return NULL;
}


static qemuMigrationCookieNetworkPtr
qemuMigrationCookieNetworkXMLParse(xmlXPathContextPtr ctxt)
{
    qemuMigrationCookieNetworkPtr optr;
    size_t i;
    int n;
    xmlNodePtr *interfaces = NULL;
    char *vporttype;
    xmlNodePtr save_ctxt = ctxt->node;

    if (VIR_ALLOC(optr) < 0)
        goto error;

    if ((n = virXPathNodeSet("./network/interface", ctxt, &interfaces)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing interface information"));
        goto error;
    }

    optr->nnets = n;
    if (VIR_ALLOC_N(optr->net, optr->nnets) < 0)
        goto error;

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

 error:
    VIR_FREE(interfaces);
    qemuMigrationCookieNetworkFree(optr);
    optr = NULL;
    goto cleanup;
}


static qemuMigrationCookieNBDPtr
qemuMigrationCookieNBDXMLParse(xmlXPathContextPtr ctxt)
{
    qemuMigrationCookieNBDPtr ret = NULL;
    char *port = NULL, *capacity = NULL;
    size_t i;
    int n;
    xmlNodePtr *disks = NULL;
    xmlNodePtr save_ctxt = ctxt->node;

    if (VIR_ALLOC(ret) < 0)
        goto error;

    port = virXPathString("string(./nbd/@port)", ctxt);
    if (port && virStrToLong_i(port, NULL, 10, &ret->port) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed nbd port '%s'"),
                       port);
        goto error;
    }

    /* Now check if source sent a list of disks to prealloc. We might be
     * talking to an older server, so it's not an error if the list is
     * missing. */
    if ((n = virXPathNodeSet("./nbd/disk", ctxt, &disks)) > 0) {
        if (VIR_ALLOC_N(ret->disks, n) < 0)
            goto error;
        ret->ndisks = n;

        for (i = 0; i < n; i++) {
            ctxt->node = disks[i];
            VIR_FREE(capacity);

            if (!(ret->disks[i].target = virXPathString("string(./@target)", ctxt))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Malformed disk target"));
                goto error;
            }

            capacity = virXPathString("string(./@capacity)", ctxt);
            if (!capacity ||
                virStrToLong_ull(capacity, NULL, 10,
                                 &ret->disks[i].capacity) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Malformed disk capacity: '%s'"),
                               NULLSTR(capacity));
                goto error;
            }
        }
    }

 cleanup:
    VIR_FREE(port);
    VIR_FREE(capacity);
    VIR_FREE(disks);
    ctxt->node = save_ctxt;
    return ret;
 error:
    qemuMigrationCookieNBDFree(ret);
    ret = NULL;
    goto cleanup;
}


static qemuDomainJobInfoPtr
qemuMigrationCookieStatisticsXMLParse(xmlXPathContextPtr ctxt)
{
    qemuDomainJobInfoPtr jobInfo = NULL;
    qemuMonitorMigrationStats *stats;
    xmlNodePtr save_ctxt = ctxt->node;

    if (!(ctxt->node = virXPathNode("./statistics", ctxt)))
        goto cleanup;

    if (VIR_ALLOC(jobInfo) < 0)
        goto cleanup;

    stats = &jobInfo->stats;
    jobInfo->type = VIR_DOMAIN_JOB_COMPLETED;

    virXPathULongLong("string(./started[1])", ctxt, &jobInfo->started);
    virXPathULongLong("string(./stopped[1])", ctxt, &jobInfo->stopped);
    virXPathULongLong("string(./sent[1])", ctxt, &jobInfo->sent);
    if (virXPathLongLong("string(./delta[1])", ctxt, &jobInfo->timeDelta) == 0)
        jobInfo->timeDeltaSet = true;

    virXPathULongLong("string(./" VIR_DOMAIN_JOB_TIME_ELAPSED "[1])",
                      ctxt, &jobInfo->timeElapsed);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_TIME_REMAINING "[1])",
                      ctxt, &jobInfo->timeRemaining);

    if (virXPathULongLong("string(./" VIR_DOMAIN_JOB_DOWNTIME "[1])",
                          ctxt, &stats->downtime) == 0)
        stats->downtime_set = true;
    if (virXPathULongLong("string(./" VIR_DOMAIN_JOB_SETUP_TIME "[1])",
                          ctxt, &stats->setup_time) == 0)
        stats->setup_time_set = true;

    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_TOTAL "[1])",
                      ctxt, &stats->ram_total);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_PROCESSED "[1])",
                      ctxt, &stats->ram_transferred);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_REMAINING "[1])",
                      ctxt, &stats->ram_remaining);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_BPS "[1])",
                      ctxt, &stats->ram_bps);

    if (virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_CONSTANT "[1])",
                          ctxt, &stats->ram_duplicate) == 0)
        stats->ram_duplicate_set = true;
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_NORMAL "[1])",
                      ctxt, &stats->ram_normal);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES "[1])",
                      ctxt, &stats->ram_normal_bytes);

    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE "[1])",
                      ctxt, &stats->ram_dirty_rate);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_MEMORY_ITERATION "[1])",
                      ctxt, &stats->ram_iteration);

    virXPathULongLong("string(./" VIR_DOMAIN_JOB_DISK_TOTAL "[1])",
                      ctxt, &stats->disk_total);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_DISK_PROCESSED "[1])",
                      ctxt, &stats->disk_transferred);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_DISK_REMAINING "[1])",
                      ctxt, &stats->disk_remaining);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_DISK_BPS "[1])",
                      ctxt, &stats->disk_bps);

    if (virXPathULongLong("string(./" VIR_DOMAIN_JOB_COMPRESSION_CACHE "[1])",
                          ctxt, &stats->xbzrle_cache_size) == 0)
        stats->xbzrle_set = true;
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_COMPRESSION_BYTES "[1])",
                      ctxt, &stats->xbzrle_bytes);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_COMPRESSION_PAGES "[1])",
                      ctxt, &stats->xbzrle_pages);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES "[1])",
                      ctxt, &stats->xbzrle_cache_miss);
    virXPathULongLong("string(./" VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW "[1])",
                      ctxt, &stats->xbzrle_overflow);

    virXPathInt("string(./" VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE "[1])",
                ctxt, &stats->cpu_throttle_percentage);
 cleanup:
    ctxt->node = save_ctxt;
    return jobInfo;
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
    size_t i;
    int n;
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
        goto error;
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

    for (i = 0; i < n; i++) {
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
            goto error;
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
        mig->persistent = virDomainDefParseNode(doc, nodes[0],
                                                caps, driver->xmlopt, NULL,
                                                VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                VIR_DOMAIN_DEF_PARSE_ABI_UPDATE |
                                                VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
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
        virXPathBoolean("boolean(./nbd)", ctxt) &&
        (!(mig->nbd = qemuMigrationCookieNBDXMLParse(ctxt))))
        goto error;

    if (flags & QEMU_MIGRATION_COOKIE_STATS &&
        virXPathBoolean("boolean(./statistics)", ctxt) &&
        (!(mig->jobInfo = qemuMigrationCookieStatisticsXMLParse(ctxt))))
        goto error;

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


int
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

    if (flags & QEMU_MIGRATION_COOKIE_NETWORK &&
        qemuMigrationCookieAddNetwork(mig, driver, dom) < 0) {
        return -1;
    }

    if ((flags & QEMU_MIGRATION_COOKIE_NBD) &&
        qemuMigrationCookieAddNBD(mig, driver, dom) < 0)
        return -1;

    if (flags & QEMU_MIGRATION_COOKIE_STATS &&
        qemuMigrationCookieAddStatistics(mig, dom) < 0)
        return -1;

    if (flags & QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG)
        mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG;

    if (flags & QEMU_MIGRATION_COOKIE_CPU_HOTPLUG)
        mig->flagsMandatory |= QEMU_MIGRATION_COOKIE_CPU_HOTPLUG;

    if (!(*cookieout = qemuMigrationCookieXMLFormatStr(driver, mig)))
        return -1;

    *cookieoutlen = strlen(*cookieout) + 1;

    VIR_DEBUG("cookielen=%d cookie=%s", *cookieoutlen, *cookieout);

    return 0;
}


qemuMigrationCookiePtr
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

    if (flags & QEMU_MIGRATION_COOKIE_PERSISTENT &&
        mig->persistent &&
        STRNEQ(dom->def->name, mig->persistent->name)) {
        VIR_FREE(mig->persistent->name);
        if (VIR_STRDUP(mig->persistent->name, dom->def->name) < 0)
            goto error;
    }

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
