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

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration_params");

#define QEMU_MIGRATION_TLS_ALIAS_BASE "libvirt_migrate"


qemuMigrationParamsPtr
qemuMigrationParamsNew(void)
{
    qemuMigrationParamsPtr params;

    if (VIR_ALLOC(params) < 0)
        return NULL;

    return params;
}


void
qemuMigrationParamsFree(qemuMigrationParamsPtr migParams)
{
    if (!migParams)
        return;

    VIR_FREE(migParams->params.tlsCreds);
    VIR_FREE(migParams->params.tlsHostname);
    VIR_FREE(migParams);
}


qemuMigrationParamsPtr
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned long flags)
{
    qemuMigrationParamsPtr migParams;

    if (!(migParams = qemuMigrationParamsNew()))
        return NULL;

    if (!params)
        return migParams;

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

    GET(AUTO_CONVERGE_INITIAL, cpuThrottleInitial);
    GET(AUTO_CONVERGE_INCREMENT, cpuThrottleIncrement);

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


int
qemuMigrationParamsSet(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob,
                       qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (qemuMonitorSetMigrationParams(priv->mon, &migParams->params) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}


/* qemuMigrationParamsCheckTLSCreds
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 *
 * Query the migration parameters looking for the 'tls-creds' parameter.
 * If found, then we can support setting or clearing the parameters and thus
 * can support TLS for migration.
 *
 * Returns 0 if we were able to successfully fetch the params and
 * additionally if the tls-creds parameter exists, saves it in the
 * private domain structure. Returns -1 on failure.
 */
static int
qemuMigrationParamsCheckTLSCreds(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 int asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationParamsPtr migParams = NULL;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (!(migParams = qemuMigrationParamsNew()))
        goto cleanup;

    if (qemuMonitorGetMigrationParams(priv->mon, &migParams->params) < 0)
        goto cleanup;

    /* NB: Could steal NULL pointer too! Let caller decide what to do. */
    VIR_STEAL_PTR(priv->migTLSAlias, migParams->params.tlsCreds);

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    qemuMigrationParamsFree(migParams);

    return ret;
}


/* qemuMigrationParamsCheckSetupTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @cfg: configuration pointer
 * @asyncJob: migration job to join
 *
 * Check if TLS is possible and set up the environment. Assumes the caller
 * desires to use TLS (e.g. caller found VIR_MIGRATE_TLS flag).
 *
 * Ensure the qemu.conf has been properly configured to add an entry for
 * "migrate_tls_x509_cert_dir". Also check if the "tls-creds" parameter
 * was present from a query of migration parameters
 *
 * Returns 0 on success, -1 on error/failure
 */
int
qemuMigrationParamsCheckSetupTLS(virQEMUDriverPtr driver,
                                 virQEMUDriverConfigPtr cfg,
                                 virDomainObjPtr vm,
                                 int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!cfg->migrateTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("host migration TLS directory not configured"));
        return -1;
    }

    if (qemuMigrationParamsCheckTLSCreds(driver, vm, asyncJob) < 0)
        return -1;

    if (!priv->migTLSAlias) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TLS migration is not supported with this "
                         "QEMU binary"));
        return -1;
    }

    /* If there's a secret, then grab/store it now using the connection */
    if (cfg->migrateTLSx509secretUUID &&
        !(priv->migSecinfo =
          qemuDomainSecretInfoTLSNew(priv, QEMU_MIGRATION_TLS_ALIAS_BASE,
                                     cfg->migrateTLSx509secretUUID)))
        return -1;

    return 0;
}


/* qemuMigrationParamsAddTLSObjects
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @cfg: configuration pointer
 * @tlsListen: server or client
 * @asyncJob: Migration job to join
 * @tlsAlias: alias to be generated for TLS object
 * @secAlias: alias to be generated for a secinfo object
 * @migParams: migration parameters to set
 *
 * Create the TLS objects for the migration and set the migParams value
 *
 * Returns 0 on success, -1 on failure
 */
int
qemuMigrationParamsAddTLSObjects(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virQEMUDriverConfigPtr cfg,
                                 bool tlsListen,
                                 int asyncJob,
                                 char **tlsAlias,
                                 char **secAlias,
                                 qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr tlsProps = NULL;
    virJSONValuePtr secProps = NULL;

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

    if (VIR_STRDUP(migParams->params.tlsCreds, *tlsAlias) < 0)
        goto error;

    return 0;

 error:
    virJSONValueFree(tlsProps);
    virJSONValueFree(secProps);
    return -1;
}


/* qemuMigrationParamsSetEmptyTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 * @migParams: Pointer to a migration parameters block
 *
 * If we support setting the tls-creds, then set both tls-creds and
 * tls-hostname to the empty string ("") which indicates to not use
 * TLS on this migration.
 *
 * Returns 0 on success, -1 on failure
 */
int
qemuMigrationParamsSetEmptyTLS(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               int asyncJob,
                               qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuMigrationParamsCheckTLSCreds(driver, vm, asyncJob) < 0)
        return -1;

    if (!priv->migTLSAlias)
        return 0;

    if (VIR_STRDUP(migParams->params.tlsCreds, "") < 0 ||
        VIR_STRDUP(migParams->params.tlsHostname, "") < 0)
        return -1;

    return 0;
}


int
qemuMigrationParamsSetCompression(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  int asyncJob,
                                  qemuMigrationCompressionPtr compression,
                                  qemuMigrationParamsPtr migParams)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuMigrationOptionSet(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_XBZRLE,
                               compression->methods &
                               (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE),
                               asyncJob) < 0)
        return -1;

    if (qemuMigrationOptionSet(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_COMPRESS,
                               compression->methods &
                               (1ULL << QEMU_MIGRATION_COMPRESS_MT),
                               asyncJob) < 0)
        return -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    migParams->params.compressLevel_set = compression->level_set;
    migParams->params.compressLevel = compression->level;

    migParams->params.compressThreads_set = compression->threads_set;
    migParams->params.compressThreads = compression->threads;

    migParams->params.decompressThreads_set = compression->dthreads_set;
    migParams->params.decompressThreads = compression->dthreads;

    if (compression->xbzrle_cache_set &&
        qemuMonitorSetMigrationCacheSize(priv->mon,
                                         compression->xbzrle_cache) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
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
 */
int
qemuMigrationParamsCheck(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationParamsPtr origParams = NULL;
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (!(origParams = qemuMigrationParamsNew()))
        goto cleanup;

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
    qemuMonitorMigrationCaps cap;
    virErrorPtr err = virSaveLastError();

    VIR_DEBUG("Resetting migration parameters %p", origParams);

    if (!virDomainObjIsActive(vm))
        goto cleanup;

    if (origParams) {
        if (qemuMigrationParamsSet(driver, vm, asyncJob, origParams) < 0)
            goto cleanup;
        qemuMigrationParamsResetTLS(driver, vm, asyncJob, origParams);
    }

    for (cap = 0; cap < QEMU_MONITOR_MIGRATION_CAPS_LAST; cap++) {
        if (qemuMigrationCapsGet(vm, cap) &&
            qemuMigrationOptionSet(driver, vm, cap, false, asyncJob) < 0)
            goto cleanup;
    }

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
        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            goto cleanup;

        rc = qemuMonitorSetMigrationCapability(priv->mon,
                                               QEMU_MONITOR_MIGRATION_CAPS_EVENTS,
                                               true);

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
