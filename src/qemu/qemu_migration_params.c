/*
 * qemu_migration_params.c: QEMU migration parameters handling
 *
 * Copyright (C) 2006-2018 Red Hat, Inc.
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

#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"

#include "qemu_alias.h"
#include "qemu_hotplug.h"
#include "qemu_migration.h"
#include "qemu_migration_params.h"
#include "qemu_monitor.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration_params");

#define QEMU_MIGRATION_TLS_ALIAS_BASE "libvirt_migrate"

struct _qemuMigrationParams {
    virBitmapPtr caps;
    qemuMonitorMigrationParams params;
};

typedef struct _qemuMigrationParamsAlwaysOnItem qemuMigrationParamsAlwaysOnItem;
struct _qemuMigrationParamsAlwaysOnItem {
    qemuMonitorMigrationCaps cap;
    int party; /* bit-wise OR of qemuMigrationParty */
};

typedef struct _qemuMigrationParamsFlagMapItem qemuMigrationParamsFlagMapItem;
struct _qemuMigrationParamsFlagMapItem {
    virDomainMigrateFlags flag;
    qemuMonitorMigrationCaps cap;
    int party; /* bit-wise OR of qemuMigrationParty */
};

/* Migration capabilities which should always be enabled as long as they
 * are supported by QEMU. */
static const qemuMigrationParamsAlwaysOnItem qemuMigrationParamsAlwaysOn[] = {
    {QEMU_MONITOR_MIGRATION_CAPS_PAUSE_BEFORE_SWITCHOVER,
     QEMU_MIGRATION_SOURCE},
};

/* Translation from virDomainMigrateFlags to qemuMonitorMigrationCaps. */
static const qemuMigrationParamsFlagMapItem qemuMigrationParamsFlagMap[] = {
    {VIR_MIGRATE_RDMA_PIN_ALL,
     QEMU_MONITOR_MIGRATION_CAPS_RDMA_PIN_ALL,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {VIR_MIGRATE_AUTO_CONVERGE,
     QEMU_MONITOR_MIGRATION_CAPS_AUTO_CONVERGE,
     QEMU_MIGRATION_SOURCE},

    {VIR_MIGRATE_POSTCOPY,
     QEMU_MONITOR_MIGRATION_CAPS_POSTCOPY,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},
};


static qemuMigrationParamsPtr
qemuMigrationParamsNew(void)
{
    qemuMigrationParamsPtr params;

    if (VIR_ALLOC(params) < 0)
        return NULL;

    params->caps = virBitmapNew(QEMU_MONITOR_MIGRATION_CAPS_LAST);
    if (!params->caps)
        goto error;

    return params;

 error:
    qemuMigrationParamsFree(params);
    return NULL;
}


void
qemuMigrationParamsFree(qemuMigrationParamsPtr migParams)
{
    if (!migParams)
        return;

    virBitmapFree(migParams->caps);
    VIR_FREE(migParams->params.tlsCreds);
    VIR_FREE(migParams->params.tlsHostname);
    VIR_FREE(migParams);
}


qemuMigrationParamsPtr
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned long flags,
                             qemuMigrationParty party)
{
    qemuMigrationParamsPtr migParams;
    size_t i;

    if (!(migParams = qemuMigrationParamsNew()))
        return NULL;

    for (i = 0; i < ARRAY_CARDINALITY(qemuMigrationParamsFlagMap); i++) {
        qemuMonitorMigrationCaps cap = qemuMigrationParamsFlagMap[i].cap;

        if (qemuMigrationParamsFlagMap[i].party & party &&
            flags & qemuMigrationParamsFlagMap[i].flag) {
            VIR_DEBUG("Enabling migration capability '%s'",
                      qemuMonitorMigrationCapsTypeToString(cap));
            ignore_value(virBitmapSetBit(migParams->caps, cap));
        }
    }

#define GET(PARAM, VAR) \
    do { \
        int rc; \
        if ((rc = virTypedParamsGetInt(params, nparams, \
                                       VIR_MIGRATE_PARAM_ ## PARAM, \
                                       &migParams->params.VAR)) < 0) \
            goto error; \
 \
        if (rc == 1) \
            migParams->params.VAR ## _set = true; \
    } while (0)

    if (params) {
        if (party == QEMU_MIGRATION_SOURCE) {
            GET(AUTO_CONVERGE_INITIAL, cpuThrottleInitial);
            GET(AUTO_CONVERGE_INCREMENT, cpuThrottleIncrement);
        }
    }

#undef GET

    if ((migParams->params.cpuThrottleInitial_set ||
         migParams->params.cpuThrottleIncrement_set) &&
        !(flags & VIR_MIGRATE_AUTO_CONVERGE)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn auto convergence on to tune it"));
        goto error;
    }

    return migParams;

 error:
    qemuMigrationParamsFree(migParams);
    return NULL;
}


/**
 * qemuMigrationParamsApply
 * @driver: qemu driver
 * @vm: domain object
 * @asyncJob: migration job
 * @migParams: migration parameters to send to QEMU
 *
 * Send all parameters stored in @migParams to QEMU.
 *
 * Returns 0 on success, -1 on failure.
 */
int
qemuMigrationParamsApply(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool xbzrleCacheSize_old = false;
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (qemuMonitorSetMigrationCapabilities(priv->mon, priv->migrationCaps,
                                            migParams->caps) < 0)
        goto cleanup;

    /* If QEMU is too old to support xbzrle-cache-size migration parameter,
     * we need to set it via migrate-set-cache-size and tell
     * qemuMonitorSetMigrationParams to ignore this parameter.
     */
    if (migParams->params.xbzrleCacheSize_set &&
        (!priv->job.migParams ||
         !priv->job.migParams->params.xbzrleCacheSize_set)) {
        if (qemuMonitorSetMigrationCacheSize(priv->mon,
                                             migParams->params.xbzrleCacheSize) < 0)
            goto cleanup;
        xbzrleCacheSize_old = true;
        migParams->params.xbzrleCacheSize_set = false;
    }

    if (qemuMonitorSetMigrationParams(priv->mon, &migParams->params) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (xbzrleCacheSize_old)
        migParams->params.xbzrleCacheSize_set = true;

    return ret;
}


static int
qemuMigrationParamsSetCapability(virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                 qemuMonitorMigrationCaps capability,
                                 bool state,
                                 qemuMigrationParamsPtr migParams)
{
    if (state)
        ignore_value(virBitmapSetBit(migParams->caps, capability));
    else
        ignore_value(virBitmapClearBit(migParams->caps, capability));

    return 0;
}


/* qemuMigrationParamsEnableTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @tlsListen: server or client
 * @asyncJob: Migration job to join
 * @tlsAlias: alias to be generated for TLS object
 * @secAlias: alias to be generated for a secinfo object
 * @hostname: hostname of the migration destination
 * @migParams: migration parameters to set
 *
 * Create the TLS objects for the migration and set the migParams value.
 * If QEMU itself does not connect to the destination @hostname must be
 * provided for certificate verification.
 *
 * Returns 0 on success, -1 on failure
 */
int
qemuMigrationParamsEnableTLS(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             bool tlsListen,
                             int asyncJob,
                             char **tlsAlias,
                             char **secAlias,
                             const char *hostname,
                             qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr tlsProps = NULL;
    virJSONValuePtr secProps = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    if (!cfg->migrateTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("host migration TLS directory not configured"));
        goto error;
    }

    if ((!priv->job.migParams->params.tlsCreds)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TLS migration is not supported with this "
                         "QEMU binary"));
        goto error;
    }

    /* If there's a secret, then grab/store it now using the connection */
    if (cfg->migrateTLSx509secretUUID &&
        !(priv->migSecinfo =
          qemuDomainSecretInfoTLSNew(priv, QEMU_MIGRATION_TLS_ALIAS_BASE,
                                     cfg->migrateTLSx509secretUUID)))
        goto error;

    if (qemuDomainGetTLSObjects(priv->qemuCaps, priv->migSecinfo,
                                cfg->migrateTLSx509certdir, tlsListen,
                                cfg->migrateTLSx509verify,
                                QEMU_MIGRATION_TLS_ALIAS_BASE,
                                &tlsProps, tlsAlias, &secProps, secAlias) < 0)
        goto error;

    /* Ensure the domain doesn't already have the TLS objects defined...
     * This should prevent any issues just in case some cleanup wasn't
     * properly completed (both src and dst use the same alias) or
     * some other error path between now and perform . */
    qemuDomainDelTLSObjects(driver, vm, asyncJob, *secAlias, *tlsAlias);

    if (qemuDomainAddTLSObjects(driver, vm, asyncJob, *secAlias, &secProps,
                                *tlsAlias, &tlsProps) < 0)
        goto error;

    if (VIR_STRDUP(migParams->params.tlsCreds, *tlsAlias) < 0 ||
        VIR_STRDUP(migParams->params.tlsHostname, hostname ? hostname : "") < 0)
        goto error;

    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;

 error:
    virJSONValueFree(tlsProps);
    virJSONValueFree(secProps);
    goto cleanup;
}


/* qemuMigrationParamsDisableTLS
 * @vm: domain object
 * @migParams: Pointer to a migration parameters block
 *
 * If we support setting the tls-creds, then set both tls-creds and
 * tls-hostname to the empty string ("") which indicates to not use
 * TLS on this migration.
 *
 * Returns 0 on success, -1 on failure
 */
int
qemuMigrationParamsDisableTLS(virDomainObjPtr vm,
                              qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->job.migParams->params.tlsCreds)
        return 0;

    if (VIR_STRDUP(migParams->params.tlsCreds, "") < 0 ||
        VIR_STRDUP(migParams->params.tlsHostname, "") < 0)
        return -1;

    return 0;
}


int
qemuMigrationParamsSetCompression(virDomainObjPtr vm,
                                  qemuMigrationCompressionPtr compression,
                                  qemuMigrationParamsPtr migParams)
{
    if (qemuMigrationParamsSetCapability(vm,
                                         QEMU_MONITOR_MIGRATION_CAPS_XBZRLE,
                                         compression->methods &
                                         (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE),
                                         migParams) < 0)
        return -1;

    if (qemuMigrationParamsSetCapability(vm,
                                         QEMU_MONITOR_MIGRATION_CAPS_COMPRESS,
                                         compression->methods &
                                         (1ULL << QEMU_MIGRATION_COMPRESS_MT),
                                         migParams) < 0)
        return -1;

    migParams->params.compressLevel_set = compression->level_set;
    migParams->params.compressLevel = compression->level;

    migParams->params.compressThreads_set = compression->threads_set;
    migParams->params.compressThreads = compression->threads;

    migParams->params.decompressThreads_set = compression->dthreads_set;
    migParams->params.decompressThreads = compression->dthreads;

    migParams->params.xbzrleCacheSize_set = compression->xbzrle_cache_set;
    migParams->params.xbzrleCacheSize = compression->xbzrle_cache;

    return 0;
}


/* qemuMigrationParamsResetTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 *
 * Deconstruct all the setup possibly done for TLS - delete the TLS and
 * security objects, free the secinfo, and reset the migration params to "".
 */
static void
qemuMigrationParamsResetTLS(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            int asyncJob,
                            qemuMigrationParamsPtr origParams)
{
    char *tlsAlias = NULL;
    char *secAlias = NULL;

    /* If QEMU does not support TLS migration we didn't set the aliases. */
    if (!origParams->params.tlsCreds)
        return;

    /* NB: If either or both fail to allocate memory we can still proceed
     *     since the next time we migrate another deletion attempt will be
     *     made after successfully generating the aliases. */
    tlsAlias = qemuAliasTLSObjFromSrcAlias(QEMU_MIGRATION_TLS_ALIAS_BASE);
    secAlias = qemuDomainGetSecretAESAlias(QEMU_MIGRATION_TLS_ALIAS_BASE, false);

    qemuDomainDelTLSObjects(driver, vm, asyncJob, secAlias, tlsAlias);
    qemuDomainSecretInfoFree(&QEMU_DOMAIN_PRIVATE(vm)->migSecinfo);

    VIR_FREE(tlsAlias);
    VIR_FREE(secAlias);
}


/**
 * qemuMigrationParamsCheck:
 *
 * Check supported migration parameters and keep their original values in
 * qemuDomainJobObj so that we can properly reset them at the end of migration.
 * Reports an error if any of the currently used capabilities in @migParams
 * are unsupported by QEMU.
 */
int
qemuMigrationParamsCheck(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationParamsPtr origParams = NULL;
    qemuMonitorMigrationCaps cap;
    qemuMigrationParty party;
    size_t i;
    int ret = -1;

    if (asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT)
        party = QEMU_MIGRATION_SOURCE;
    else
        party = QEMU_MIGRATION_DESTINATION;

    for (cap = 0; cap < QEMU_MONITOR_MIGRATION_CAPS_LAST; cap++) {
        bool state = false;

        ignore_value(virBitmapGetBit(migParams->caps, cap, &state));

        if (state && !qemuMigrationCapsGet(vm, cap)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("Migration option '%s' is not supported by QEMU binary"),
                           qemuMonitorMigrationCapsTypeToString(cap));
            return -1;
        }
    }

    for (i = 0; i < ARRAY_CARDINALITY(qemuMigrationParamsAlwaysOn); i++) {
        cap = qemuMigrationParamsAlwaysOn[i].cap;

        if (qemuMigrationParamsAlwaysOn[i].party & party &&
            qemuMigrationCapsGet(vm, cap)) {
            VIR_DEBUG("Enabling migration capability '%s'",
                      qemuMonitorMigrationCapsTypeToString(cap));
            ignore_value(virBitmapSetBit(migParams->caps, cap));
        }
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (!(origParams = qemuMigrationParamsNew()))
        goto cleanup;

    /*
     * We want to disable all migration capabilities after migration, no need
     * to ask QEMU for their current settings.
     */

    if (qemuMonitorGetMigrationParams(priv->mon, &origParams->params) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret == 0)
        VIR_STEAL_PTR(priv->job.migParams, origParams);
    qemuMigrationParamsFree(origParams);

    return ret;
}


/*
 * qemuMigrationParamsReset:
 *
 * Reset all migration parameters so that the next job which internally uses
 * migration (save, managedsave, snapshots, dump) will not try to use them.
 */
void
qemuMigrationParamsReset(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr origParams)
{
    virErrorPtr err = virSaveLastError();

    VIR_DEBUG("Resetting migration parameters %p", origParams);

    if (!virDomainObjIsActive(vm) || !origParams)
        goto cleanup;

    if (qemuMigrationParamsApply(driver, vm, asyncJob, origParams) < 0)
        goto cleanup;

    qemuMigrationParamsResetTLS(driver, vm, asyncJob, origParams);

 cleanup:
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
}


int
qemuMigrationCapsCheck(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virBitmapPtr migEvent = NULL;
    char **caps = NULL;
    char **capStr;
    int ret = -1;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetMigrationCapabilities(priv->mon, &caps);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    if (!caps) {
        ret = 0;
        goto cleanup;
    }

    priv->migrationCaps = virBitmapNew(QEMU_MONITOR_MIGRATION_CAPS_LAST);
    if (!priv->migrationCaps)
        goto cleanup;

    for (capStr = caps; *capStr; capStr++) {
        int cap = qemuMonitorMigrationCapsTypeFromString(*capStr);

        if (cap < 0) {
            VIR_DEBUG("Unknown migration capability: '%s'", *capStr);
        } else {
            ignore_value(virBitmapSetBit(priv->migrationCaps, cap));
            VIR_DEBUG("Found migration capability: '%s'", *capStr);
        }
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT)) {
        migEvent = virBitmapNew(QEMU_MONITOR_MIGRATION_CAPS_LAST);
        if (!migEvent)
            goto cleanup;

        ignore_value(virBitmapSetBit(migEvent, QEMU_MONITOR_MIGRATION_CAPS_EVENTS));

        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            goto cleanup;

        rc = qemuMonitorSetMigrationCapabilities(priv->mon, migEvent, migEvent);

        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;

        if (rc < 0) {
            virResetLastError();
            VIR_DEBUG("Cannot enable migration events; clearing capability");
            virQEMUCapsClear(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
        }
    }

    /* Migration events capability must always be enabled, clearing it from
     * migration capabilities bitmap makes sure it won't be touched anywhere
     * else.
     */
    ignore_value(virBitmapClearBit(priv->migrationCaps,
                                   QEMU_MONITOR_MIGRATION_CAPS_EVENTS));

    ret = 0;

 cleanup:
    virStringListFree(caps);
    return ret;
}


bool
qemuMigrationCapsGet(virDomainObjPtr vm,
                     qemuMonitorMigrationCaps cap)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool enabled = false;

    if (priv->migrationCaps)
        ignore_value(virBitmapGetBit(priv->migrationCaps, cap, &enabled));

    return enabled;
}
