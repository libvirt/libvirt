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
#define LIBVIRT_QEMU_MIGRATION_PARAMSPRIV_H_ALLOW
#include "qemu_migration_paramspriv.h"
#include "qemu_monitor.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration_params");

#define QEMU_MIGRATION_TLS_ALIAS_BASE "libvirt_migrate"

typedef enum {
    QEMU_MIGRATION_PARAM_TYPE_INT,
    QEMU_MIGRATION_PARAM_TYPE_ULL,
    QEMU_MIGRATION_PARAM_TYPE_BOOL,
    QEMU_MIGRATION_PARAM_TYPE_STRING,
} qemuMigrationParamType;

typedef struct _qemuMigrationParamValue qemuMigrationParamValue;
typedef qemuMigrationParamValue *qemuMigrationParamValuePtr;
struct _qemuMigrationParamValue {
    bool set;
    union {
        int i; /* exempt from syntax-check */
        unsigned long long ull;
        bool b;
        char *s;
    } value;
};

struct _qemuMigrationParams {
    unsigned long long compMethods; /* bit-wise OR of qemuMigrationCompressMethod */
    virBitmapPtr caps;
    qemuMigrationParamValue params[QEMU_MIGRATION_PARAM_LAST];
};

typedef enum {
    QEMU_MIGRATION_COMPRESS_XBZRLE = 0,
    QEMU_MIGRATION_COMPRESS_MT,

    QEMU_MIGRATION_COMPRESS_LAST
} qemuMigrationCompressMethod;
VIR_ENUM_DECL(qemuMigrationCompressMethod);
VIR_ENUM_IMPL(qemuMigrationCompressMethod,
              QEMU_MIGRATION_COMPRESS_LAST,
              "xbzrle",
              "mt",
);

VIR_ENUM_IMPL(qemuMigrationCapability,
              QEMU_MIGRATION_CAP_LAST,
              "xbzrle",
              "auto-converge",
              "rdma-pin-all",
              "events",
              "postcopy-ram",
              "compress",
              "pause-before-switchover",
              "late-block-activate",
              "multifd",
);


VIR_ENUM_DECL(qemuMigrationParam);
VIR_ENUM_IMPL(qemuMigrationParam,
              QEMU_MIGRATION_PARAM_LAST,
              "compress-level",
              "compress-threads",
              "decompress-threads",
              "cpu-throttle-initial",
              "cpu-throttle-increment",
              "tls-creds",
              "tls-hostname",
              "max-bandwidth",
              "downtime-limit",
              "block-incremental",
              "xbzrle-cache-size",
              "max-postcopy-bandwidth",
              "multifd-channels",
);

typedef struct _qemuMigrationParamsAlwaysOnItem qemuMigrationParamsAlwaysOnItem;
struct _qemuMigrationParamsAlwaysOnItem {
    qemuMigrationCapability cap;
    int party; /* bit-wise OR of qemuMigrationParty */
};

typedef struct _qemuMigrationParamsFlagMapItem qemuMigrationParamsFlagMapItem;
struct _qemuMigrationParamsFlagMapItem {
    virDomainMigrateFlags flag;
    qemuMigrationCapability cap;
    int party; /* bit-wise OR of qemuMigrationParty */
};

typedef struct _qemuMigrationParamsTPMapItem qemuMigrationParamsTPMapItem;
struct _qemuMigrationParamsTPMapItem {
    const char *typedParam;
    unsigned int unit;
    qemuMigrationParam param;
    int party; /* bit-wise OR of qemuMigrationParty */
};

/* Migration capabilities which should always be enabled as long as they
 * are supported by QEMU. If the capability is supposed to be enabled on both
 * sides of migration, it won't be enabled unless both sides support it.
 */
static const qemuMigrationParamsAlwaysOnItem qemuMigrationParamsAlwaysOn[] = {
    {QEMU_MIGRATION_CAP_PAUSE_BEFORE_SWITCHOVER,
     QEMU_MIGRATION_SOURCE},

    {QEMU_MIGRATION_CAP_LATE_BLOCK_ACTIVATE,
     QEMU_MIGRATION_DESTINATION},
};

/* Translation from virDomainMigrateFlags to qemuMigrationCapability. */
static const qemuMigrationParamsFlagMapItem qemuMigrationParamsFlagMap[] = {
    {VIR_MIGRATE_RDMA_PIN_ALL,
     QEMU_MIGRATION_CAP_RDMA_PIN_ALL,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {VIR_MIGRATE_AUTO_CONVERGE,
     QEMU_MIGRATION_CAP_AUTO_CONVERGE,
     QEMU_MIGRATION_SOURCE},

    {VIR_MIGRATE_POSTCOPY,
     QEMU_MIGRATION_CAP_POSTCOPY,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {VIR_MIGRATE_PARALLEL,
     QEMU_MIGRATION_CAP_MULTIFD,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},
};

/* Translation from VIR_MIGRATE_PARAM_* typed parameters to
 * qemuMigrationParams. */
static const qemuMigrationParamsTPMapItem qemuMigrationParamsTPMap[] = {
    {.typedParam = VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL,
     .param = QEMU_MIGRATION_PARAM_THROTTLE_INITIAL,
     .party = QEMU_MIGRATION_SOURCE},

    {.typedParam = VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT,
     .param = QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT,
     .party = QEMU_MIGRATION_SOURCE},

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL,
     .param = QEMU_MIGRATION_PARAM_COMPRESS_LEVEL,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS,
     .param = QEMU_MIGRATION_PARAM_COMPRESS_THREADS,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS,
     .param = QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE,
     .param = QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY,
     .unit = 1024 * 1024, /* MiB/s */
     .param = QEMU_MIGRATION_PARAM_MAX_POSTCOPY_BANDWIDTH,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS,
     .param = QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},
};

static const qemuMigrationParamType qemuMigrationParamTypes[] = {
    [QEMU_MIGRATION_PARAM_COMPRESS_LEVEL] = QEMU_MIGRATION_PARAM_TYPE_INT,
    [QEMU_MIGRATION_PARAM_COMPRESS_THREADS] = QEMU_MIGRATION_PARAM_TYPE_INT,
    [QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS] = QEMU_MIGRATION_PARAM_TYPE_INT,
    [QEMU_MIGRATION_PARAM_THROTTLE_INITIAL] = QEMU_MIGRATION_PARAM_TYPE_INT,
    [QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT] = QEMU_MIGRATION_PARAM_TYPE_INT,
    [QEMU_MIGRATION_PARAM_TLS_CREDS] = QEMU_MIGRATION_PARAM_TYPE_STRING,
    [QEMU_MIGRATION_PARAM_TLS_HOSTNAME] = QEMU_MIGRATION_PARAM_TYPE_STRING,
    [QEMU_MIGRATION_PARAM_MAX_BANDWIDTH] = QEMU_MIGRATION_PARAM_TYPE_ULL,
    [QEMU_MIGRATION_PARAM_DOWNTIME_LIMIT] = QEMU_MIGRATION_PARAM_TYPE_ULL,
    [QEMU_MIGRATION_PARAM_BLOCK_INCREMENTAL] = QEMU_MIGRATION_PARAM_TYPE_BOOL,
    [QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE] = QEMU_MIGRATION_PARAM_TYPE_ULL,
    [QEMU_MIGRATION_PARAM_MAX_POSTCOPY_BANDWIDTH] = QEMU_MIGRATION_PARAM_TYPE_ULL,
    [QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS] = QEMU_MIGRATION_PARAM_TYPE_INT,
};
verify(G_N_ELEMENTS(qemuMigrationParamTypes) == QEMU_MIGRATION_PARAM_LAST);


virBitmapPtr
qemuMigrationParamsGetAlwaysOnCaps(qemuMigrationParty party)
{
    virBitmapPtr caps = NULL;
    size_t i;

    if (!(caps = virBitmapNew(QEMU_MIGRATION_CAP_LAST)))
        return NULL;

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsAlwaysOn); i++) {
        if (!(qemuMigrationParamsAlwaysOn[i].party & party))
            continue;

        ignore_value(virBitmapSetBit(caps, qemuMigrationParamsAlwaysOn[i].cap));
    }

    return caps;
}


qemuMigrationParamsPtr
qemuMigrationParamsNew(void)
{
    qemuMigrationParamsPtr params;

    if (VIR_ALLOC(params) < 0)
        return NULL;

    params->caps = virBitmapNew(QEMU_MIGRATION_CAP_LAST);
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
    size_t i;

    if (!migParams)
        return;

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        if (qemuMigrationParamTypes[i] == QEMU_MIGRATION_PARAM_TYPE_STRING)
            VIR_FREE(migParams->params[i].value.s);
    }

    virBitmapFree(migParams->caps);
    VIR_FREE(migParams);
}


static int
qemuMigrationParamsCheckType(qemuMigrationParam param,
                             qemuMigrationParamType type)
{
    if (qemuMigrationParamTypes[param] != type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Type mismatch for '%s' migration parameter"),
                       qemuMigrationParamTypeToString(param));
        return -1;
    }

    return 0;
}


static int
qemuMigrationParamsGetTPInt(qemuMigrationParamsPtr migParams,
                            qemuMigrationParam param,
                            virTypedParameterPtr params,
                            int nparams,
                            const char *name,
                            unsigned int unit)
{
    int rc;

    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_INT) < 0)
        return -1;

    if (!params)
        return 0;

    if ((rc = virTypedParamsGetInt(params, nparams, name,
                                   &migParams->params[param].value.i)) < 0)
        return -1;

    if (unit > 0) {
        unsigned int max = UINT_MAX / unit;
        if (migParams->params[param].value.i > max) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("migration parameter '%s' must be less than %u"),
                           name, max + 1);
            return -1;
        }
        migParams->params[param].value.i *= unit;
    }

    migParams->params[param].set = !!rc;
    return 0;
}


static int
qemuMigrationParamsSetTPInt(qemuMigrationParamsPtr migParams,
                            qemuMigrationParam param,
                            virTypedParameterPtr *params,
                            int *nparams,
                            int *maxparams,
                            const char *name,
                            unsigned int unit)
{
    int value;

    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_INT) < 0)
        return -1;

    if (!migParams->params[param].set)
        return 0;

    value = migParams->params[param].value.i;
    if (unit > 0)
        value /= unit;

    return virTypedParamsAddInt(params, nparams, maxparams, name, value);
}


static int
qemuMigrationParamsGetTPULL(qemuMigrationParamsPtr migParams,
                            qemuMigrationParam param,
                            virTypedParameterPtr params,
                            int nparams,
                            const char *name,
                            unsigned int unit)
{
    int rc;

    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_ULL) < 0)
        return -1;

    if (!params)
        return 0;

    if ((rc = virTypedParamsGetULLong(params, nparams, name,
                                      &migParams->params[param].value.ull)) < 0)
        return -1;

    if (unit > 0) {
        unsigned long long max = ULLONG_MAX / unit;
        if (migParams->params[param].value.ull > max) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("migration parameter '%s' must be less than %llu"),
                           name, max + 1);
            return -1;
        }
        migParams->params[param].value.ull *= unit;
    }

    migParams->params[param].set = !!rc;
    return 0;
}


static int
qemuMigrationParamsSetTPULL(qemuMigrationParamsPtr migParams,
                            qemuMigrationParam param,
                            virTypedParameterPtr *params,
                            int *nparams,
                            int *maxparams,
                            const char *name,
                            unsigned int unit)
{
    unsigned long long value;

    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_ULL) < 0)
        return -1;

    if (!migParams->params[param].set)
        return 0;

    value = migParams->params[param].value.ull;
    if (unit > 0)
        value /= unit;

    return virTypedParamsAddULLong(params, nparams, maxparams, name, value);
}


static int
qemuMigrationParamsSetCompression(virTypedParameterPtr params,
                                  int nparams,
                                  unsigned long flags,
                                  qemuMigrationParamsPtr migParams)
{
    size_t i;
    int method;
    qemuMigrationCapability cap;

    for (i = 0; i < nparams; i++) {
        if (STRNEQ(params[i].field, VIR_MIGRATE_PARAM_COMPRESSION))
            continue;

        method = qemuMigrationCompressMethodTypeFromString(params[i].value.s);
        if (method < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported compression method '%s'"),
                           params[i].value.s);
            goto error;
        }

        if (migParams->compMethods & (1ULL << method)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Compression method '%s' is specified twice"),
                           params[i].value.s);
            goto error;
        }

        migParams->compMethods |= 1ULL << method;

        switch ((qemuMigrationCompressMethod) method) {
        case QEMU_MIGRATION_COMPRESS_XBZRLE:
            cap = QEMU_MIGRATION_CAP_XBZRLE;
            break;

        case QEMU_MIGRATION_COMPRESS_MT:
            cap = QEMU_MIGRATION_CAP_COMPRESS;
            break;

        case QEMU_MIGRATION_COMPRESS_LAST:
        default:
            continue;
        }
        ignore_value(virBitmapSetBit(migParams->caps, cap));
    }

    if ((migParams->params[QEMU_MIGRATION_PARAM_COMPRESS_LEVEL].set ||
         migParams->params[QEMU_MIGRATION_PARAM_COMPRESS_THREADS].set ||
         migParams->params[QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS].set) &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_MT))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn multithread compression on to tune it"));
        goto error;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE].set &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn xbzrle compression on to tune it"));
        goto error;
    }

    if (!migParams->compMethods && (flags & VIR_MIGRATE_COMPRESSED)) {
        migParams->compMethods = 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE;
        ignore_value(virBitmapSetBit(migParams->caps,
                                     QEMU_MIGRATION_CAP_XBZRLE));
    }

    return 0;

 error:
    return -1;
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

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsFlagMap); i++) {
        qemuMigrationCapability cap = qemuMigrationParamsFlagMap[i].cap;

        if (qemuMigrationParamsFlagMap[i].party & party &&
            flags & qemuMigrationParamsFlagMap[i].flag) {
            VIR_DEBUG("Enabling migration capability '%s'",
                      qemuMigrationCapabilityTypeToString(cap));
            ignore_value(virBitmapSetBit(migParams->caps, cap));
        }
    }

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsTPMap); i++) {
        const qemuMigrationParamsTPMapItem *item = &qemuMigrationParamsTPMap[i];

        if (!(item->party & party))
            continue;

        VIR_DEBUG("Setting migration parameter '%s' from '%s'",
                  qemuMigrationParamTypeToString(item->param), item->typedParam);

        switch (qemuMigrationParamTypes[item->param]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            if (qemuMigrationParamsGetTPInt(migParams, item->param, params,
                                            nparams, item->typedParam,
                                            item->unit) < 0)
                goto error;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            if (qemuMigrationParamsGetTPULL(migParams, item->param, params,
                                            nparams, item->typedParam,
                                            item->unit) < 0)
                goto error;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            break;
        }
    }

    if ((migParams->params[QEMU_MIGRATION_PARAM_THROTTLE_INITIAL].set ||
         migParams->params[QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT].set) &&
        !(flags & VIR_MIGRATE_AUTO_CONVERGE)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn auto convergence on to tune it"));
        goto error;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS].set &&
        !(flags & VIR_MIGRATE_PARALLEL)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn parallel migration on to tune it"));
        goto error;
    }

    if (qemuMigrationParamsSetCompression(params, nparams, flags, migParams) < 0)
        goto error;

    return migParams;

 error:
    qemuMigrationParamsFree(migParams);
    return NULL;
}


int
qemuMigrationParamsDump(qemuMigrationParamsPtr migParams,
                        virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        unsigned long *flags)
{
    size_t i;

    if (migParams->compMethods == 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE &&
        !migParams->params[QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE].set) {
        *flags |= VIR_MIGRATE_COMPRESSED;
        return 0;
    }

    for (i = 0; i < QEMU_MIGRATION_COMPRESS_LAST; ++i) {
        if ((migParams->compMethods & (1ULL << i)) &&
            virTypedParamsAddString(params, nparams, maxparams,
                                    VIR_MIGRATE_PARAM_COMPRESSION,
                                    qemuMigrationCompressMethodTypeToString(i)) < 0)
            return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsTPMap); i++) {
        const qemuMigrationParamsTPMapItem *item = &qemuMigrationParamsTPMap[i];

        if (!(item->party & QEMU_MIGRATION_DESTINATION))
            continue;

        switch (qemuMigrationParamTypes[item->param]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            if (qemuMigrationParamsSetTPInt(migParams, item->param,
                                            params, nparams, maxparams,
                                            item->typedParam, item->unit) < 0)
                return -1;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            if (qemuMigrationParamsSetTPULL(migParams, item->param,
                                            params, nparams, maxparams,
                                            item->typedParam, item->unit) < 0)
                return -1;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            break;
        }
    }

    return 0;
}


qemuMigrationParamsPtr
qemuMigrationParamsFromJSON(virJSONValuePtr params)
{
    qemuMigrationParamsPtr migParams;
    qemuMigrationParamValuePtr pv;
    const char *name;
    const char *str;
    size_t i;

    if (!(migParams = qemuMigrationParamsNew()))
        return NULL;

    if (!params)
        return migParams;

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        name = qemuMigrationParamTypeToString(i);
        pv = &migParams->params[i];

        switch (qemuMigrationParamTypes[i]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            if (virJSONValueObjectGetNumberInt(params, name, &pv->value.i) == 0)
                pv->set = true;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            if (virJSONValueObjectGetNumberUlong(params, name, &pv->value.ull) == 0)
                pv->set = true;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            if (virJSONValueObjectGetBoolean(params, name, &pv->value.b) == 0)
                pv->set = true;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            if ((str = virJSONValueObjectGetString(params, name))) {
                if (VIR_STRDUP(pv->value.s, str) < 0)
                    goto error;
                pv->set = true;
            }
            break;
        }
    }

    return migParams;

 error:
    qemuMigrationParamsFree(migParams);
    return NULL;
}


virJSONValuePtr
qemuMigrationParamsToJSON(qemuMigrationParamsPtr migParams)
{
    virJSONValuePtr params = NULL;
    qemuMigrationParamValuePtr pv;
    const char *name;
    size_t i;
    int rc;

    if (!(params = virJSONValueNewObject()))
        return NULL;

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        name = qemuMigrationParamTypeToString(i);
        pv = &migParams->params[i];

        if (!pv->set)
            continue;

        rc = 0;
        switch (qemuMigrationParamTypes[i]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            rc = virJSONValueObjectAppendNumberInt(params, name, pv->value.i);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            rc = virJSONValueObjectAppendNumberUlong(params, name, pv->value.ull);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            rc = virJSONValueObjectAppendBoolean(params, name, pv->value.b);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            rc = virJSONValueObjectAppendString(params, name, pv->value.s);
            break;
        }

        if (rc < 0)
            goto error;
    }

    return params;

 error:
    virJSONValueFree(params);
    return NULL;
}


virJSONValuePtr
qemuMigrationCapsToJSON(virBitmapPtr caps,
                        virBitmapPtr states)
{
    virJSONValuePtr json = NULL;
    virJSONValuePtr cap = NULL;
    qemuMigrationCapability bit;
    const char *name;

    if (!(json = virJSONValueNewArray()))
        return NULL;

    for (bit = 0; bit < QEMU_MIGRATION_CAP_LAST; bit++) {
        bool supported = false;
        bool state = false;

        ignore_value(virBitmapGetBit(caps, bit, &supported));
        if (!supported)
            continue;

        ignore_value(virBitmapGetBit(states, bit, &state));

        if (!(cap = virJSONValueNewObject()))
            goto error;

        name = qemuMigrationCapabilityTypeToString(bit);
        if (virJSONValueObjectAppendString(cap, "capability", name) < 0)
            goto error;

        if (virJSONValueObjectAppendBoolean(cap, "state", state) < 0)
            goto error;

        if (virJSONValueArrayAppend(json, cap) < 0)
            goto error;

        cap = NULL;
    }

    return json;

 error:
    virJSONValueFree(json);
    virJSONValueFree(cap);
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
    virJSONValuePtr params = NULL;
    virJSONValuePtr caps = NULL;
    qemuMigrationParam xbzrle = QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE;
    int ret = -1;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (asyncJob == QEMU_ASYNC_JOB_NONE) {
        if (!virBitmapIsAllClear(migParams->caps)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Migration capabilities can only be set by "
                             "a migration job"));
            goto cleanup;
        }
    } else {
        if (!(caps = qemuMigrationCapsToJSON(priv->migrationCaps, migParams->caps)))
            goto cleanup;

        if (virJSONValueArraySize(caps) > 0) {
            rc = qemuMonitorSetMigrationCapabilities(priv->mon, caps);
            caps = NULL;
            if (rc < 0)
                goto cleanup;
        }
    }

    /* If QEMU is too old to support xbzrle-cache-size migration parameter,
     * we need to set it via migrate-set-cache-size and tell
     * qemuMonitorSetMigrationParams to ignore this parameter.
     */
    if (migParams->params[xbzrle].set &&
        (!priv->job.migParams ||
         !priv->job.migParams->params[xbzrle].set)) {
        if (qemuMonitorSetMigrationCacheSize(priv->mon,
                                             migParams->params[xbzrle].value.ull) < 0)
            goto cleanup;
        xbzrleCacheSize_old = true;
        migParams->params[xbzrle].set = false;
    }

    if (!(params = qemuMigrationParamsToJSON(migParams)))
        goto cleanup;

    if (virJSONValueObjectKeysNumber(params) > 0) {
        rc = qemuMonitorSetMigrationParams(priv->mon, params);
        params = NULL;
        if (rc < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (xbzrleCacheSize_old)
        migParams->params[xbzrle].set = true;

    virJSONValueFree(params);
    virJSONValueFree(caps);

    return ret;
}


/**
 * qemuMigrationParamsSetString:
 * @migrParams: migration parameter object
 * @param: parameter to set
 * @value: new value
 *
 * Enables and sets the migration parameter @param in @migrParams. Returns 0 on
 * success and -1 on error. Libvirt error is reported.
 */
static int
qemuMigrationParamsSetString(qemuMigrationParamsPtr migParams,
                             qemuMigrationParam param,
                             const char *value)
{
    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_STRING) < 0)
        return -1;

    if (VIR_STRDUP(migParams->params[param].value.s, value) < 0)
        return -1;

    migParams->params[param].set = true;

    return 0;
}


/* qemuMigrationParamsEnableTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @tlsListen: server or client
 * @asyncJob: Migration job to join
 * @tlsAlias: alias to be generated for TLS object
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
                             const char *hostname,
                             qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr tlsProps = NULL;
    virJSONValuePtr secProps = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *secAlias = NULL;
    int ret = -1;

    if (!cfg->migrateTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("host migration TLS directory not configured"));
        goto error;
    }

    if (!priv->job.migParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TLS migration is not supported with this "
                         "QEMU binary"));
        goto error;
    }

    /* If there's a secret, then grab/store it now using the connection */
    if (cfg->migrateTLSx509secretUUID) {
        if (!(priv->migSecinfo =
              qemuDomainSecretInfoTLSNew(priv, QEMU_MIGRATION_TLS_ALIAS_BASE,
                                         cfg->migrateTLSx509secretUUID)))
            goto error;
        secAlias = priv->migSecinfo->s.aes.alias;
    }

    if (!(*tlsAlias = qemuAliasTLSObjFromSrcAlias(QEMU_MIGRATION_TLS_ALIAS_BASE)))
        goto error;

    if (qemuDomainGetTLSObjects(priv->qemuCaps, priv->migSecinfo,
                                cfg->migrateTLSx509certdir, tlsListen,
                                cfg->migrateTLSx509verify,
                                *tlsAlias, &tlsProps, &secProps) < 0)
        goto error;

    /* Ensure the domain doesn't already have the TLS objects defined...
     * This should prevent any issues just in case some cleanup wasn't
     * properly completed (both src and dst use the same alias) or
     * some other error path between now and perform . */
    qemuDomainDelTLSObjects(driver, vm, asyncJob, secAlias, *tlsAlias);

    if (qemuDomainAddTLSObjects(driver, vm, asyncJob, &secProps, &tlsProps) < 0)
        goto error;

    if (qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_CREDS,
                                     *tlsAlias) < 0 ||
        qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_HOSTNAME,
                                     NULLSTR_EMPTY(hostname)) < 0)
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

    if (!priv->job.migParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set)
        return 0;

    if (qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_CREDS, "") < 0 ||
        qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_HOSTNAME, "") < 0)
        return -1;

    return 0;
}


/* qemuMigrationParamsResetTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 * @apiFlags: API flags used to start the migration
 *
 * Deconstruct all the setup possibly done for TLS - delete the TLS and
 * security objects, free the secinfo, and reset the migration params to "".
 */
static void
qemuMigrationParamsResetTLS(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            int asyncJob,
                            qemuMigrationParamsPtr origParams,
                            unsigned long apiFlags)
{
    char *tlsAlias = NULL;
    char *secAlias = NULL;

    /* There's nothing to do if QEMU does not support TLS migration or we were
     * not asked to enable it. */
    if (!origParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set ||
        !(apiFlags & VIR_MIGRATE_TLS))
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


int
qemuMigrationParamsFetch(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr *migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr jsonParams = NULL;
    int ret = -1;
    int rc;

    *migParams = NULL;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuMonitorGetMigrationParams(priv->mon, &jsonParams);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    if (!(*migParams = qemuMigrationParamsFromJSON(jsonParams)))
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(jsonParams);
    return ret;
}


int
qemuMigrationParamsSetULL(qemuMigrationParamsPtr migParams,
                          qemuMigrationParam param,
                          unsigned long long value)
{
    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_ULL) < 0)
        return -1;

    migParams->params[param].value.ull = value;
    migParams->params[param].set = true;
    return 0;
}


/**
 * Returns -1 on error,
 *          0 on success,
 *          1 if the parameter is not supported by QEMU.
 */
int
qemuMigrationParamsGetULL(qemuMigrationParamsPtr migParams,
                          qemuMigrationParam param,
                          unsigned long long *value)
{
    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_ULL) < 0)
        return -1;

    if (!migParams->params[param].set)
        return 1;

    *value = migParams->params[param].value.ull;
    return 0;
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
                         qemuMigrationParamsPtr migParams,
                         virBitmapPtr remoteCaps)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationCapability cap;
    qemuMigrationParty party;
    size_t i;

    if (asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT)
        party = QEMU_MIGRATION_SOURCE;
    else
        party = QEMU_MIGRATION_DESTINATION;

    for (cap = 0; cap < QEMU_MIGRATION_CAP_LAST; cap++) {
        bool state = false;

        ignore_value(virBitmapGetBit(migParams->caps, cap, &state));

        if (state && !qemuMigrationCapsGet(vm, cap)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("Migration option '%s' is not supported by QEMU binary"),
                           qemuMigrationCapabilityTypeToString(cap));
            return -1;
        }
    }

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsAlwaysOn); i++) {
        cap = qemuMigrationParamsAlwaysOn[i].cap;

        if (qemuMigrationParamsAlwaysOn[i].party & party &&
            qemuMigrationCapsGet(vm, cap)) {
            if (qemuMigrationParamsAlwaysOn[i].party != party) {
                bool remote = false;

                if (remoteCaps)
                    ignore_value(virBitmapGetBit(remoteCaps, cap, &remote));

                if (!remote) {
                    VIR_DEBUG("Not enabling migration capability '%s'; it is "
                              "not supported or automatically enabled by the "
                              "other side of migration",
                              qemuMigrationCapabilityTypeToString(cap));
                    continue;
                }
            }

            VIR_DEBUG("Enabling migration capability '%s'",
                      qemuMigrationCapabilityTypeToString(cap));
            ignore_value(virBitmapSetBit(migParams->caps, cap));
        }
    }

    /*
     * We want to disable all migration capabilities after migration, no need
     * to ask QEMU for their current settings.
     */

    return qemuMigrationParamsFetch(driver, vm, asyncJob, &priv->job.migParams);
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
                         qemuMigrationParamsPtr origParams,
                         unsigned long apiFlags)
{
    virErrorPtr err = virSaveLastError();

    VIR_DEBUG("Resetting migration parameters %p, flags 0x%lx",
              origParams, apiFlags);

    if (!virDomainObjIsActive(vm) || !origParams)
        goto cleanup;

    if (qemuMigrationParamsApply(driver, vm, asyncJob, origParams) < 0)
        goto cleanup;

    qemuMigrationParamsResetTLS(driver, vm, asyncJob, origParams, apiFlags);

 cleanup:
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
}


void
qemuMigrationParamsFormat(virBufferPtr buf,
                          qemuMigrationParamsPtr migParams)
{
    qemuMigrationParamValuePtr pv;
    size_t i;

    virBufferAddLit(buf, "<migParams>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        pv = &migParams->params[i];

        if (!pv->set)
            continue;

        virBufferAsprintf(buf, "<param name='%s' ",
                          qemuMigrationParamTypeToString(i));

        switch (qemuMigrationParamTypes[i]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            virBufferAsprintf(buf, "value='%d'", pv->value.i);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            virBufferAsprintf(buf, "value='%llu'", pv->value.ull);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            virBufferAsprintf(buf, "value='%s'", pv->value.b ? "yes" : "no");
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            virBufferEscapeString(buf, "value='%s'", pv->value.s);
            break;
        }

        virBufferAddLit(buf, "/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</migParams>\n");
}


int
qemuMigrationParamsParse(xmlXPathContextPtr ctxt,
                         qemuMigrationParamsPtr *migParams)
{
    qemuMigrationParamsPtr params = NULL;
    qemuMigrationParamValuePtr pv;
    xmlNodePtr *nodes = NULL;
    char *name = NULL;
    char *value = NULL;
    int param;
    size_t i;
    int rc;
    int n;
    int ret = -1;

    *migParams = NULL;

    if ((rc = virXPathBoolean("boolean(./migParams)", ctxt)) < 0)
        goto cleanup;

    if (rc == 0) {
        ret = 0;
        goto cleanup;
    }

    if ((n = virXPathNodeSet("./migParams[1]/param", ctxt, &nodes)) < 0)
        return -1;

    if (!(params = qemuMigrationParamsNew()))
        goto cleanup;

    for (i = 0; i < n; i++) {
        if (!(name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing migration parameter name"));
            goto cleanup;
        }

        if ((param = qemuMigrationParamTypeFromString(name)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown migration parameter '%s'"), name);
            goto cleanup;
        }
        pv = &params->params[param];

        if (!(value = virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing value for migration parameter '%s'"),
                           name);
            goto cleanup;
        }

        rc = 0;
        switch (qemuMigrationParamTypes[param]) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            rc = virStrToLong_i(value, NULL, 10, &pv->value.i);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            rc = virStrToLong_ullp(value, NULL, 10, &pv->value.ull);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            if (STREQ(value, "yes"))
                pv->value.b = true;
            else if (STREQ(value, "no"))
                pv->value.b = false;
            else
                rc = -1;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            VIR_STEAL_PTR(pv->value.s, value);
            break;
        }

        if (rc < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid value '%s' for migration parameter '%s'"),
                           value, name);
            goto cleanup;
        }

        pv->set = true;
        VIR_FREE(name);
        VIR_FREE(value);
    }

    VIR_STEAL_PTR(*migParams, params);
    ret = 0;

 cleanup:
    qemuMigrationParamsFree(params);
    VIR_FREE(nodes);
    VIR_FREE(name);
    VIR_FREE(value);
    return ret;
}


int
qemuMigrationCapsCheck(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virBitmapPtr migEvent = NULL;
    virJSONValuePtr json = NULL;
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

    priv->migrationCaps = virBitmapNew(QEMU_MIGRATION_CAP_LAST);
    if (!priv->migrationCaps)
        goto cleanup;

    for (capStr = caps; *capStr; capStr++) {
        int cap = qemuMigrationCapabilityTypeFromString(*capStr);

        if (cap < 0) {
            VIR_DEBUG("Unknown migration capability: '%s'", *capStr);
        } else {
            ignore_value(virBitmapSetBit(priv->migrationCaps, cap));
            VIR_DEBUG("Found migration capability: '%s'", *capStr);
        }
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT)) {
        migEvent = virBitmapNew(QEMU_MIGRATION_CAP_LAST);
        if (!migEvent)
            goto cleanup;

        ignore_value(virBitmapSetBit(migEvent, QEMU_MIGRATION_CAP_EVENTS));

        if (!(json = qemuMigrationCapsToJSON(migEvent, migEvent)))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            goto cleanup;

        rc = qemuMonitorSetMigrationCapabilities(priv->mon, json);
        json = NULL;

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
                                   QEMU_MIGRATION_CAP_EVENTS));

    ret = 0;

 cleanup:
    virBitmapFree(migEvent);
    virJSONValueFree(json);
    virStringListFree(caps);
    return ret;
}


bool
qemuMigrationCapsGet(virDomainObjPtr vm,
                     qemuMigrationCapability cap)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool enabled = false;

    if (priv->migrationCaps)
        ignore_value(virBitmapGetBit(priv->migrationCaps, cap, &enabled));

    return enabled;
}
