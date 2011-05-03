/*
 * qemu_migration.c: QEMU migration handling
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 *
 */

#include <config.h>

#include <sys/time.h>

#include "qemu_migration.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_capabilities.h"
#include "qemu_audit.h"
#include "qemu_cgroup.h"

#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "files.h"
#include "datatypes.h"
#include "fdstream.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define timeval_to_ms(tv)       (((tv).tv_sec * 1000ull) + ((tv).tv_usec / 1000))


bool
qemuMigrationIsAllowed(virDomainDefPtr def)
{
    if (def->nhostdevs > 0) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
            "%s", _("Domain with assigned host devices cannot be migrated"));
        return false;
    }

    return true;
}

/** qemuMigrationSetOffline
 * Pause domain for non-live migration.
 */
int
qemuMigrationSetOffline(struct qemud_driver *driver,
                        virDomainObjPtr vm)
{
    int ret;

    ret = qemuProcessStopCPUs(driver, vm);
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


int
qemuMigrationWaitForCompletion(struct qemud_driver *driver, virDomainObjPtr vm)
{
    int ret = -1;
    int status;
    unsigned long long memProcessed;
    unsigned long long memRemaining;
    unsigned long long memTotal;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    while (priv->jobInfo.type == VIR_DOMAIN_JOB_UNBOUNDED) {
        /* Poll every 50ms for progress & to allow cancellation */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000ull };
        struct timeval now;
        int rc;
        const char *job;

        switch (priv->jobActive) {
            case QEMU_JOB_MIGRATION_OUT:
                job = _("migration job");
                break;
            case QEMU_JOB_SAVE:
                job = _("domain save job");
                break;
            case QEMU_JOB_DUMP:
                job = _("domain core dump job");
                break;
            default:
                job = _("job");
        }


        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, _("%s: %s"),
                            job, _("guest unexpectedly quit"));
            goto cleanup;
        }

        if (priv->jobSignals & QEMU_JOB_SIGNAL_CANCEL) {
            priv->jobSignals ^= QEMU_JOB_SIGNAL_CANCEL;
            VIR_DEBUG0("Cancelling job at client request");
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorMigrateCancel(priv->mon);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0) {
                VIR_WARN0("Unable to cancel job");
            }
        } else if (priv->jobSignals & QEMU_JOB_SIGNAL_SUSPEND) {
            priv->jobSignals ^= QEMU_JOB_SIGNAL_SUSPEND;
            VIR_DEBUG0("Pausing domain for non-live migration");
            if (qemuMigrationSetOffline(driver, vm) < 0)
                VIR_WARN0("Unable to pause domain");
        } else if (priv->jobSignals & QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME) {
            unsigned long long ms = priv->jobSignalsData.migrateDowntime;

            priv->jobSignals ^= QEMU_JOB_SIGNAL_MIGRATE_DOWNTIME;
            priv->jobSignalsData.migrateDowntime = 0;
            VIR_DEBUG("Setting migration downtime to %llums", ms);
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorSetMigrationDowntime(priv->mon, ms);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0)
                VIR_WARN0("Unable to set migration downtime");
        } else if (priv->jobSignals & QEMU_JOB_SIGNAL_MIGRATE_SPEED) {
            unsigned long bandwidth = priv->jobSignalsData.migrateBandwidth;

            priv->jobSignals ^= QEMU_JOB_SIGNAL_MIGRATE_SPEED;
            priv->jobSignalsData.migrateBandwidth = 0;
            VIR_DEBUG("Setting migration bandwidth to %luMbs", bandwidth);
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            rc = qemuMonitorSetMigrationSpeed(priv->mon, bandwidth);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            if (rc < 0)
                VIR_WARN0("Unable to set migration speed");
        }

        /* Repeat check because the job signals might have caused
         * guest to die
         */
        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, _("%s: %s"),
                            job, _("guest unexpectedly quit"));
            goto cleanup;
        }

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        rc = qemuMonitorGetMigrationStatus(priv->mon,
                                           &status,
                                           &memProcessed,
                                           &memRemaining,
                                           &memTotal);
        qemuDomainObjExitMonitorWithDriver(driver, vm);

        if (rc < 0) {
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            goto cleanup;
        }

        if (gettimeofday(&now, NULL) < 0) {
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            virReportSystemError(errno, "%s",
                                 _("cannot get time of day"));
            goto cleanup;
        }
        priv->jobInfo.timeElapsed = timeval_to_ms(now) - priv->jobStart;

        switch (status) {
        case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
            priv->jobInfo.type = VIR_DOMAIN_JOB_NONE;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("%s: %s"), job, _("is not active"));
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
            priv->jobInfo.dataTotal = memTotal;
            priv->jobInfo.dataRemaining = memRemaining;
            priv->jobInfo.dataProcessed = memProcessed;

            priv->jobInfo.memTotal = memTotal;
            priv->jobInfo.memRemaining = memRemaining;
            priv->jobInfo.memProcessed = memProcessed;
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
            priv->jobInfo.type = VIR_DOMAIN_JOB_COMPLETED;
            ret = 0;
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
            priv->jobInfo.type = VIR_DOMAIN_JOB_FAILED;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("%s: %s"), job, _("unexpectedly failed"));
            break;

        case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
            priv->jobInfo.type = VIR_DOMAIN_JOB_CANCELLED;
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("%s: %s"), job, _("canceled by client"));
            break;
        }

        virDomainObjUnlock(vm);
        qemuDriverUnlock(driver);

        nanosleep(&ts, NULL);

        qemuDriverLock(driver);
        virDomainObjLock(vm);
    }

cleanup:
    return ret;
}


/* Prepare is the first step, and it runs on the destination host.
 *
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
int
qemuMigrationPrepareTunnel(struct qemud_driver *driver,
                           virConnectPtr dconn,
                           virStreamPtr st,
                           const char *dname,
                           const char *dom_xml)
{
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int internalret;
    int dataFD[2] = { -1, -1 };
    virBitmapPtr qemuCaps = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (!qemuMigrationIsAllowed(def))
        goto cleanup;

    /* Target domain name, maybe renamed. */
    if (dname) {
        VIR_FREE(def->name);
        def->name = strdup(dname);
        if (def->name == NULL)
            goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, true))) {
        /* virDomainAssignDef already set the error */
        goto cleanup;
    }
    def = NULL;
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (pipe(dataFD) < 0 ||
        virSetCloseExec(dataFD[1]) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto endjob;
    }

    /* check that this qemu version supports the interactive exec */
    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL, &qemuCaps) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot determine QEMU argv syntax %s"),
                        vm->def->emulator);
        goto endjob;
    }
    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming stdio (which qemu_command might convert to exec:cat or fd:n)
     */
    internalret = qemuProcessStart(dconn, driver, vm, "stdio", true, dataFD[0],
                                   NULL, VIR_VM_OP_MIGRATE_IN_START);
    if (internalret < 0) {
        qemuAuditDomainStart(vm, "migrated", false);
        /* Note that we don't set an error here because qemuProcessStart
         * should have already done that.
         */
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto endjob;
    }

    if (virFDStreamOpen(st, dataFD[1]) < 0) {
        qemuAuditDomainStart(vm, "migrated", false);
        qemuProcessStop(driver, vm, 0);
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        virReportSystemError(errno, "%s",
                             _("cannot pass pipe for tunnelled migration"));
        goto endjob;
    }
    dataFD[1] = -1; /* 'st' owns the FD now & will close it */

    qemuAuditDomainStart(vm, "migrated", true);

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

    /* We set a fake job active which is held across
     * API calls until the finish() call. This prevents
     * any other APIs being invoked while incoming
     * migration is taking place
     */
    if (vm &&
        virDomainObjIsActive(vm)) {
        priv->jobActive = QEMU_JOB_MIGRATION_IN;
        priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;
        priv->jobStart = timeval_to_ms(now);
    }

cleanup:
    qemuCapsFree(qemuCaps);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(dataFD[0]);
    VIR_FORCE_CLOSE(dataFD[1]);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    qemuDriverUnlock(driver);
    return ret;
}


int
qemuMigrationPrepareDirect(struct qemud_driver *driver,
                           virConnectPtr dconn,
                           const char *uri_in,
                           char **uri_out,
                           const char *dname,
                           const char *dom_xml)
{
    static int port = 0;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    int this_port;
    char *hostname = NULL;
    char migrateFrom [64];
    const char *p;
    virDomainEventPtr event = NULL;
    int ret = -1;
    int internalret;
    qemuDomainObjPrivatePtr priv = NULL;
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }

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
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("hostname on destination resolved to localhost, but migration requires an FQDN"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatability with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        /* Caller frees */
        internalret = virAsprintf(uri_out, "tcp:%s:%d", hostname, this_port);
        if (internalret < 0) {
            virReportOOMError();
            goto cleanup;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STRPREFIX (uri_in, "tcp:")) {
            qemuReportError (VIR_ERR_INVALID_ARG,
                             "%s", _("only tcp URIs are supported for KVM/QEMU migrations"));
            goto cleanup;
        }

        /* Get the port number. */
        p = strrchr (uri_in, ':');
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
            this_port = virParseNumber (&p);
            if (this_port == -1 || p-uri_in != strlen (uri_in)) {
                qemuReportError(VIR_ERR_INVALID_ARG,
                                "%s", _("URI ended with incorrect ':port'"));
                goto cleanup;
            }
        }
    }

    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(driver->caps, dom_xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (!qemuMigrationIsAllowed(def))
        goto cleanup;

    /* Target domain name, maybe renamed. */
    if (dname) {
        VIR_FREE(def->name);
        def->name = strdup(dname);
        if (def->name == NULL)
            goto cleanup;
    }

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains,
                                  def, true))) {
        /* virDomainAssignDef already set the error */
        goto cleanup;
    }
    def = NULL;
    priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming tcp:0.0.0.0:port
     */
    snprintf (migrateFrom, sizeof (migrateFrom), "tcp:0.0.0.0:%d", this_port);
    if (qemuProcessStart(dconn, driver, vm, migrateFrom, true,
                         -1, NULL, VIR_VM_OP_MIGRATE_IN_START) < 0) {
        qemuAuditDomainStart(vm, "migrated", false);
        /* Note that we don't set an error here because qemuProcessStart
         * should have already done that.
         */
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
        goto endjob;
    }

    qemuAuditDomainStart(vm, "migrated", true);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    ret = 0;

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

    /* We set a fake job active which is held across
     * API calls until the finish() call. This prevents
     * any other APIs being invoked while incoming
     * migration is taking place
     */
    if (vm &&
        virDomainObjIsActive(vm)) {
        priv->jobActive = QEMU_JOB_MIGRATION_IN;
        priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;
        priv->jobStart = timeval_to_ms(now);
    }

cleanup:
    VIR_FREE(hostname);
    virDomainDefFree(def);
    if (ret != 0)
        VIR_FREE(*uri_out);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
}


/* Perform migration using QEMU's native TCP migrate support,
 * not encrypted obviously
 */
static int doNativeMigrate(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           const char *uri,
                           unsigned int flags,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    int ret = -1;
    xmlURIPtr uribits = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned int background_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;

    /* Issue the migrate command. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri, "tcp://")) {
        /* HACK: source host generates bogus URIs, so fix them up */
        char *tmpuri;
        if (virAsprintf(&tmpuri, "tcp://%s", uri + strlen("tcp:")) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        uribits = xmlParseURI(tmpuri);
        VIR_FREE(tmpuri);
    } else {
        uribits = xmlParseURI(uri);
    }
    if (!uribits) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot parse URI %s"), uri);
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (resource > 0 &&
        qemuMonitorSetMigrationSpeed(priv->mon, resource) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;

    if (flags & VIR_MIGRATE_NON_SHARED_INC)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;

    if (qemuMonitorMigrateToHost(priv->mon, background_flags, uribits->server,
                                 uribits->port) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (qemuMigrationWaitForCompletion(driver, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    xmlFreeURI(uribits);
    return ret;
}


#define TUNNEL_SEND_BUF_SIZE 65536

static int doTunnelSendAll(virStreamPtr st,
                           int sock)
{
    char *buffer;
    int nbytes = TUNNEL_SEND_BUF_SIZE;

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0) {
        virReportOOMError();
        virStreamAbort(st);
        return -1;
    }

    /* XXX should honour the 'resource' parameter here */
    for (;;) {
        nbytes = saferead(sock, buffer, nbytes);
        if (nbytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("tunnelled migration failed to read from qemu"));
            virStreamAbort(st);
            VIR_FREE(buffer);
            return -1;
        }
        else if (nbytes == 0)
            /* EOF; get out of here */
            break;

        if (virStreamSend(st, buffer, nbytes) < 0) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("Failed to write migration data to remote libvirtd"));
            VIR_FREE(buffer);
            return -1;
        }
    }

    VIR_FREE(buffer);

    if (virStreamFinish(st) < 0)
        /* virStreamFinish set the error for us */
        return -1;

    return 0;
}

static int doTunnelMigrate(struct qemud_driver *driver,
                           virConnectPtr dconn,
                           virDomainObjPtr vm,
                           const char *dom_xml,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int client_sock = -1;
    int qemu_sock = -1;
    struct sockaddr_un sa_qemu, sa_client;
    socklen_t addrlen;
    virDomainPtr ddomain = NULL;
    int retval = -1;
    virStreamPtr st = NULL;
    char *unixfile = NULL;
    int internalret;
    virBitmapPtr qemuCaps = NULL;
    int status;
    unsigned long long transferred, remaining, total;
    unsigned int background_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;

    /*
     * The order of operations is important here to avoid touching
     * the source VM until we are very sure we can successfully
     * start the migration operation.
     *
     *   1. setup local support infrastructure (eg sockets)
     *   2. setup destination fully
     *   3. start migration on source
     */


    /* Stage 1. setup local support infrastructure */

    if (virAsprintf(&unixfile, "%s/qemu.tunnelmigrate.src.%s",
                    driver->libDir, vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemu_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qemu_sock < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot open tunnelled migration socket"));
        goto cleanup;
    }
    memset(&sa_qemu, 0, sizeof(sa_qemu));
    sa_qemu.sun_family = AF_UNIX;
    if (virStrcpy(sa_qemu.sun_path, unixfile,
                  sizeof(sa_qemu.sun_path)) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Unix socket '%s' too big for destination"),
                        unixfile);
        goto cleanup;
    }
    unlink(unixfile);
    if (bind(qemu_sock, (struct sockaddr *)&sa_qemu, sizeof(sa_qemu)) < 0) {
        virReportSystemError(errno,
                             _("Cannot bind to unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }
    if (listen(qemu_sock, 1) < 0) {
        virReportSystemError(errno,
                             _("Cannot listen on unix socket '%s' for tunnelled migration"),
                             unixfile);
        goto cleanup;
    }

    if (chown(unixfile, driver->user, driver->group) < 0) {
        virReportSystemError(errno,
                             _("Cannot change unix socket '%s' owner"),
                             unixfile);
        goto cleanup;
    }

    /* check that this qemu version supports the unix migration */
    if (qemuCapsExtractVersionInfo(vm->def->emulator, vm->def->os.arch,
                                   NULL, &qemuCaps) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot extract Qemu version from '%s'"),
                        vm->def->emulator);
        goto cleanup;
    }

    if (!qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_UNIX) &&
        !qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_EXEC)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("Source qemu is too old to support tunnelled migration"));
        goto cleanup;
    }


    /* Stage 2. setup destination fully
     *
     * Once stage 2 has completed successfully, we *must* call finish
     * to cleanup the target whether we succeed or fail
     */
    st = virStreamNew(dconn, 0);
    if (st == NULL)
        /* virStreamNew only fails on OOM, and it reports the error itself */
        goto cleanup;

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    internalret = dconn->driver->domainMigratePrepareTunnel(dconn, st,
                                                            flags, dname,
                                                            resource, dom_xml);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

    if (internalret < 0)
        /* domainMigratePrepareTunnel sets the error for us */
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemoteWithDriver, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    /*   3. start migration on source */
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (flags & VIR_MIGRATE_NON_SHARED_DISK)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;
    if (flags & VIR_MIGRATE_NON_SHARED_INC)
        background_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;
    if (qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_UNIX)) {
        internalret = qemuMonitorMigrateToUnix(priv->mon, background_flags,
                                               unixfile);
    }
    else if (qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_EXEC)) {
        const char *args[] = { "nc", "-U", unixfile, NULL };
        internalret = qemuMonitorMigrateToCommand(priv->mon, QEMU_MONITOR_MIGRATE_BACKGROUND, args);
    } else {
        internalret = -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (internalret < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("tunnelled migration monitor command failed"));
        goto finish;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */

    /* it is also possible that the migrate didn't fail initially, but
     * rather failed later on.  Check the output of "info migrate"
     */
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorGetMigrationStatus(priv->mon,
                                      &status,
                                      &transferred,
                                      &remaining,
                                      &total) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        goto cancel;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (status == QEMU_MONITOR_MIGRATION_STATUS_ERROR) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s",_("migrate failed"));
        goto cancel;
    }

    addrlen = sizeof(sa_client);
    while ((client_sock = accept(qemu_sock, (struct sockaddr *)&sa_client, &addrlen)) < 0) {
        if (errno == EAGAIN || errno == EINTR)
            continue;
        virReportSystemError(errno, "%s",
                             _("tunnelled migration failed to accept from qemu"));
        goto cancel;
    }

    retval = doTunnelSendAll(st, client_sock);

cancel:
    if (retval != 0 && virDomainObjIsActive(vm)) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        qemuMonitorMigrateCancel(priv->mon);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

finish:
    dname = dname ? dname : vm->def->name;
    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri, flags, retval);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

cleanup:
    VIR_FORCE_CLOSE(client_sock);
    VIR_FORCE_CLOSE(qemu_sock);
    qemuCapsFree(qemuCaps);

    if (ddomain)
        virUnrefDomain(ddomain);

    if (unixfile) {
        unlink(unixfile);
        VIR_FREE(unixfile);
    }

    if (st)
        /* don't call virStreamFree(), because that resets any pending errors */
        virUnrefStream(st);
    return retval;
}


/* This is essentially a simplified re-impl of
 * virDomainMigrateVersion2 from libvirt.c, but running in source
 * libvirtd context, instead of client app context */
static int doNonTunnelMigrate(struct qemud_driver *driver,
                              virConnectPtr dconn,
                              virDomainObjPtr vm,
                              const char *dom_xml,
                              const char *uri ATTRIBUTE_UNUSED,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource)
{
    virDomainPtr ddomain = NULL;
    int retval = -1;
    char *uri_out = NULL;
    int rc;

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    /* NB we don't pass 'uri' into this, since that's the libvirtd
     * URI in this context - so we let dest pick it */
    rc = dconn->driver->domainMigratePrepare2(dconn,
                                              NULL, /* cookie */
                                              0, /* cookielen */
                                              NULL, /* uri */
                                              &uri_out,
                                              flags, dname,
                                              resource, dom_xml);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (rc < 0)
        /* domainMigratePrepare2 sets the error for us */
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemoteWithDriver, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (uri_out == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("domainMigratePrepare2 did not set uri"));
        goto cleanup;
    }

    if (doNativeMigrate(driver, vm, uri_out, flags, dname, resource) < 0)
        goto finish;

    retval = 0;

finish:
    dname = dname ? dname : vm->def->name;
    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, NULL, 0, uri_out, flags, retval);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

    if (ddomain)
        virUnrefDomain(ddomain);

cleanup:
    return retval;
}


static int doPeer2PeerMigrate(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *uri,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource)
{
    int ret = -1;
    virConnectPtr dconn = NULL;
    char *dom_xml;
    bool p2p;

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    dconn = virConnectOpen(uri);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (dconn == NULL) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("Failed to connect to remote libvirt URI %s"), uri);
        return -1;
    }

    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
    qemuDomainObjExitRemoteWithDriver(driver, vm);
    if (!p2p) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    /* domain may have been stopped while we were talking to remote daemon */
    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    dom_xml = qemuDomainFormatXML(driver, vm,
                                  VIR_DOMAIN_XML_SECURE |
                                  VIR_DOMAIN_XML_UPDATE_CPU);
    if (!dom_xml) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("failed to get domain xml"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(driver, dconn, vm, dom_xml, uri, flags, dname, resource);
    else
        ret = doNonTunnelMigrate(driver, dconn, vm, dom_xml, uri, flags, dname, resource);

cleanup:
    VIR_FREE(dom_xml);
    /* don't call virConnectClose(), because that resets any pending errors */
    qemuDomainObjEnterRemoteWithDriver(driver, vm);
    virUnrefConnect(dconn);
    qemuDomainObjExitRemoteWithDriver(driver, vm);

    return ret;
}


int qemuMigrationPerform(struct qemud_driver *driver,
                         virConnectPtr conn,
                         virDomainObjPtr vm,
                         const char *uri,
                         unsigned long flags,
                         const char *dname,
                         unsigned long resource)
{
    virDomainEventPtr event = NULL;
    int ret = -1;
    int resume = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;
    priv->jobActive = QEMU_JOB_MIGRATION_OUT;

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto endjob;
    }

    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    priv->jobInfo.type = VIR_DOMAIN_JOB_UNBOUNDED;

    resume = vm->state == VIR_DOMAIN_RUNNING;
    if (!(flags & VIR_MIGRATE_LIVE) && vm->state == VIR_DOMAIN_RUNNING) {
        if (qemuMigrationSetOffline(driver, vm) < 0)
            goto endjob;
    }

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (doPeer2PeerMigrate(driver, vm, uri, flags, dname, resource) < 0)
            /* doPeer2PeerMigrate already set the error, so just get out */
            goto endjob;
    } else {
        if (doNativeMigrate(driver, vm, uri, flags, dname, resource) < 0)
            goto endjob;
    }

    /* Clean up the source domain. */
    qemuProcessStop(driver, vm, 1);
    qemuAuditDomainStop(vm, "migrated");
    resume = 0;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    if (!vm->persistent || (flags & VIR_MIGRATE_UNDEFINE_SOURCE)) {
        virDomainDeleteConfig(driver->configDir, driver->autostartDir, vm);
        if (qemuDomainObjEndJob(vm) > 0)
            virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }
    ret = 0;

endjob:
    if (resume && vm->state == VIR_DOMAIN_PAUSED) {
        /* we got here through some sort of failure; start the domain again */
        if (qemuProcessStartCPUs(driver, vm, conn) < 0) {
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
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return ret;
}


#if WITH_MACVTAP
static void
qemuMigrationVPAssociatePortProfiles(virDomainDefPtr def) {
    int i;
    int last_good_net = -1;
    virDomainNetDefPtr net;

    for (i = 0; i < def->nnets; i++) {
        net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            if (vpAssociatePortProfileId(net->ifname,
                                         net->mac,
                                         net->data.direct.linkdev,
                                         &net->data.direct.virtPortProfile,
                                         def->uuid,
                                         VIR_VM_OP_MIGRATE_IN_FINISH) != 0)
                goto err_exit;
        }
        last_good_net = i;
    }

    return;

err_exit:
    for (i = 0; i < last_good_net; i++) {
        net = def->nets[i];
        if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
            vpDisassociatePortProfileId(net->ifname,
                                        net->mac,
                                        net->data.direct.linkdev,
                                        &net->data.direct.virtPortProfile,
                                        VIR_VM_OP_MIGRATE_IN_FINISH);
        }
    }
}
#else /* !WITH_MACVTAP */
static void
qemuMigrationVPAssociatePortProfiles(virDomainDefPtr def ATTRIBUTE_UNUSED) { }
#endif /* WITH_MACVTAP */


virDomainPtr
qemuMigrationFinish(struct qemud_driver *driver,
                    virConnectPtr dconn,
                    virDomainObjPtr vm,
                    unsigned long flags,
                    int retcode)
{
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int newVM = 1;
    qemuDomainObjPrivatePtr priv = NULL;

    priv = vm->privateData;
    if (priv->jobActive != QEMU_JOB_MIGRATION_IN) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("domain '%s' is not processing incoming migration"), vm->def->name);
        goto cleanup;
    }
    priv->jobActive = QEMU_JOB_NONE;
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    if (qemuDomainObjBeginJobWithDriver(driver, vm) < 0)
        goto cleanup;

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto cleanup;
        }

        qemuMigrationVPAssociatePortProfiles(vm->def);

        if (flags & VIR_MIGRATE_PERSIST_DEST) {
            if (vm->persistent)
                newVM = 0;
            vm->persistent = 1;

            if (virDomainSaveConfig(driver->configDir, vm->def) < 0) {
                /* Hmpf.  Migration was successful, but making it persistent
                 * was not.  If we report successful, then when this domain
                 * shuts down, management tools are in for a surprise.  On the
                 * other hand, if we report failure, then the management tools
                 * might try to restart the domain on the source side, even
                 * though the domain is actually running on the destination.
                 * Return a NULL dom pointer, and hope that this is a rare
                 * situation and management tools are smart.
                 */
                vm = NULL;
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
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);

        if (!(flags & VIR_MIGRATE_PAUSED)) {
            /* run 'cont' on the destination, which allows migration on qemu
             * >= 0.10.6 to work properly.  This isn't strictly necessary on
             * older qemu's, but it also doesn't hurt anything there
             */
            if (qemuProcessStartCPUs(driver, vm, dconn) < 0) {
                if (virGetLastError() == NULL)
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("resume operation failed"));
                goto endjob;
            }
        }

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        if (vm->state == VIR_DOMAIN_PAUSED) {
            qemuDomainEventQueue(driver, event);
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_SUSPENDED,
                                             VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        }
        if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto endjob;
        }
    } else {
        qemuProcessStop(driver, vm, 1);
        qemuAuditDomainStop(vm, "failed");
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent) {
            if (qemuDomainObjEndJob(vm) > 0)
                virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
    }

endjob:
    if (vm &&
        qemuDomainObjEndJob(vm) == 0)
        vm = NULL;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        qemuDomainEventQueue(driver, event);
    return dom;
}

/* Helper function called while driver lock is held and vm is active.  */
int
qemuMigrationToFile(struct qemud_driver *driver, virDomainObjPtr vm,
                    virBitmapPtr qemuCaps,
                    int fd, off_t offset, const char *path,
                    const char *compressor,
                    bool is_reg, bool bypassSecurityDriver)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rc;
    bool restoreLabel = false;
    virCommandPtr cmd = NULL;
    int pipeFD[2] = { -1, -1 };

    if (qemuCaps && qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD) &&
        (!compressor || pipe(pipeFD) == 0)) {
        /* All right! We can use fd migration, which means that qemu
         * doesn't have to open() the file, so while we still have to
         * grant SELinux access, we can do it on fd and avoid cleanup
         * later, as well as skip futzing with cgroup.  */
        if (virSecurityManagerSetFDLabel(driver->securityManager, vm,
                                         compressor ? pipeFD[1] : fd) < 0)
            goto cleanup;
        bypassSecurityDriver = true;
    } else {
        /* Phooey - we have to fall back on exec migration, where qemu
         * has to popen() the file by name.  We might also stumble on
         * a race present in some qemu versions where it does a wait()
         * that botches pclose.  */
        if (!is_reg &&
            qemuCgroupControllerActive(driver,
                                       VIR_CGROUP_CONTROLLER_DEVICES)) {
            if (virCgroupForDomain(driver->cgroup, vm->def->name,
                                   &cgroup, 0) != 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unable to find cgroup for %s"),
                                vm->def->name);
                goto cleanup;
            }
            rc = virCgroupAllowDevicePath(cgroup, path,
                                          VIR_CGROUP_DEVICE_RW);
            qemuAuditCgroupPath(vm, cgroup, "allow", path, "rw", rc);
            if (rc < 0) {
                virReportSystemError(-rc,
                                     _("Unable to allow device %s for %s"),
                                     path, vm->def->name);
                goto cleanup;
            }
        }
        if ((!bypassSecurityDriver) &&
            virSecurityManagerSetSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
            goto cleanup;
        restoreLabel = true;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (!compressor) {
        const char *args[] = { "cat", NULL };

        if (qemuCaps && qemuCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_QEMU_FD) &&
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
            if (virSetCloseExec(pipeFD[1]) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to set cloexec flag"));
                qemuDomainObjExitMonitorWithDriver(driver, vm);
                goto cleanup;
            }
            if (virCommandRunAsync(cmd, NULL) < 0) {
                qemuDomainObjExitMonitorWithDriver(driver, vm);
                goto cleanup;
            }
            rc = qemuMonitorMigrateToFd(priv->mon,
                                        QEMU_MONITOR_MIGRATE_BACKGROUND,
                                        pipeFD[1]);
            if (VIR_CLOSE(pipeFD[0]) < 0 ||
                VIR_CLOSE(pipeFD[1]) < 0)
                VIR_WARN0("failed to close intermediate pipe");
        } else {
            rc = qemuMonitorMigrateToFile(priv->mon,
                                          QEMU_MONITOR_MIGRATE_BACKGROUND,
                                          args, path, offset);
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (rc < 0)
        goto cleanup;

    rc = qemuMigrationWaitForCompletion(driver, vm);

    if (rc < 0)
        goto cleanup;

    if (cmd && virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    virCommandFree(cmd);
    if (restoreLabel && (!bypassSecurityDriver) &&
        virSecurityManagerRestoreSavedStateLabel(driver->securityManager,
                                                 vm, path) < 0)
        VIR_WARN("failed to restore save state label on %s", path);

    if (cgroup != NULL) {
        rc = virCgroupDenyDevicePath(cgroup, path,
                                     VIR_CGROUP_DEVICE_RWM);
        qemuAuditCgroupPath(vm, cgroup, "deny", path, "rwm", rc);
        if (rc < 0)
            VIR_WARN("Unable to deny device %s for %s %d",
                     path, vm->def->name, rc);
        virCgroupFree(&cgroup);
    }
    return ret;
}
