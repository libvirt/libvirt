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
#include "virstring.h"

#include "qemu_alias.h"
#include "qemu_hotplug.h"
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

typedef enum {
    QEMU_MIGRATION_FLAG_REQUIRED,
    QEMU_MIGRATION_FLAG_FORBIDDEN,
} qemuMigrationFlagMatch;

typedef struct _qemuMigrationParamValue qemuMigrationParamValue;
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
    virBitmap *caps;
    qemuMigrationParamValue params[QEMU_MIGRATION_PARAM_LAST];
    virJSONValue *blockDirtyBitmapMapping;
};

typedef enum {
    QEMU_MIGRATION_COMPRESS_XBZRLE = 0,
    QEMU_MIGRATION_COMPRESS_MT,
    QEMU_MIGRATION_COMPRESS_ZLIB,
    QEMU_MIGRATION_COMPRESS_ZSTD,

    QEMU_MIGRATION_COMPRESS_LAST
} qemuMigrationCompressMethod;
VIR_ENUM_DECL(qemuMigrationCompressMethod);
VIR_ENUM_IMPL(qemuMigrationCompressMethod,
              QEMU_MIGRATION_COMPRESS_LAST,
              "xbzrle",
              "mt",
              "zlib",
              "zstd",
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
              "dirty-bitmaps",
              "return-path",
              "zero-copy-send",
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
              "multifd-compression",
              "multifd-zlib-level",
              "multifd-zstd-level",
);

typedef struct _qemuMigrationParamsAlwaysOnItem qemuMigrationParamsAlwaysOnItem;
struct _qemuMigrationParamsAlwaysOnItem {
    qemuMigrationCapability cap;
    int party; /* bit-wise OR of qemuMigrationParty */
};

typedef struct _qemuMigrationParamsFlagMapItem qemuMigrationParamsFlagMapItem;
struct _qemuMigrationParamsFlagMapItem {
    qemuMigrationFlagMatch match;
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

typedef struct _qemuMigrationParamInfoItem qemuMigrationParamInfoItem;
struct _qemuMigrationParamInfoItem {
    qemuMigrationParamType type;
    bool applyOnPostcopyResume;
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
    {QEMU_MIGRATION_FLAG_REQUIRED,
     VIR_MIGRATE_RDMA_PIN_ALL,
     QEMU_MIGRATION_CAP_RDMA_PIN_ALL,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {QEMU_MIGRATION_FLAG_REQUIRED,
     VIR_MIGRATE_AUTO_CONVERGE,
     QEMU_MIGRATION_CAP_AUTO_CONVERGE,
     QEMU_MIGRATION_SOURCE},

    {QEMU_MIGRATION_FLAG_REQUIRED,
     VIR_MIGRATE_POSTCOPY,
     QEMU_MIGRATION_CAP_POSTCOPY,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {QEMU_MIGRATION_FLAG_REQUIRED,
     VIR_MIGRATE_PARALLEL,
     QEMU_MIGRATION_CAP_MULTIFD,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {QEMU_MIGRATION_FLAG_FORBIDDEN,
     VIR_MIGRATE_TUNNELLED,
     QEMU_MIGRATION_CAP_RETURN_PATH,
     QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {QEMU_MIGRATION_FLAG_REQUIRED,
     VIR_MIGRATE_ZEROCOPY,
     QEMU_MIGRATION_CAP_ZERO_COPY_SEND,
     QEMU_MIGRATION_SOURCE},
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

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_ZLIB_LEVEL,
     .param = QEMU_MIGRATION_PARAM_MULTIFD_ZLIB_LEVEL,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_COMPRESSION_ZSTD_LEVEL,
     .param = QEMU_MIGRATION_PARAM_MULTIFD_ZSTD_LEVEL,
     .party = QEMU_MIGRATION_SOURCE | QEMU_MIGRATION_DESTINATION},

    {.typedParam = VIR_MIGRATE_PARAM_TLS_DESTINATION,
     .param = QEMU_MIGRATION_PARAM_TLS_HOSTNAME,
     .party = QEMU_MIGRATION_SOURCE},
};

static const qemuMigrationParamInfoItem qemuMigrationParamInfo[] = {
    [QEMU_MIGRATION_PARAM_COMPRESS_LEVEL] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_COMPRESS_THREADS] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_THROTTLE_INITIAL] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_TLS_CREDS] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_STRING,
    },
    [QEMU_MIGRATION_PARAM_TLS_HOSTNAME] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_STRING,
    },
    [QEMU_MIGRATION_PARAM_MAX_BANDWIDTH] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_ULL,
    },
    [QEMU_MIGRATION_PARAM_DOWNTIME_LIMIT] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_ULL,
    },
    [QEMU_MIGRATION_PARAM_BLOCK_INCREMENTAL] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_BOOL,
    },
    [QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_ULL,
    },
    [QEMU_MIGRATION_PARAM_MAX_POSTCOPY_BANDWIDTH] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_ULL,
        .applyOnPostcopyResume = true,
    },
    [QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_MULTIFD_COMPRESSION] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_STRING,
    },
    [QEMU_MIGRATION_PARAM_MULTIFD_ZLIB_LEVEL] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
    [QEMU_MIGRATION_PARAM_MULTIFD_ZSTD_LEVEL] = {
        .type = QEMU_MIGRATION_PARAM_TYPE_INT,
    },
};
G_STATIC_ASSERT(G_N_ELEMENTS(qemuMigrationParamInfo) == QEMU_MIGRATION_PARAM_LAST);


virBitmap *
qemuMigrationParamsGetAlwaysOnCaps(qemuMigrationParty party)
{
    virBitmap *caps = virBitmapNew(QEMU_MIGRATION_CAP_LAST);
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsAlwaysOn); i++) {
        if (!(qemuMigrationParamsAlwaysOn[i].party & party))
            continue;

        ignore_value(virBitmapSetBit(caps, qemuMigrationParamsAlwaysOn[i].cap));
    }

    return caps;
}


qemuMigrationParams *
qemuMigrationParamsNew(void)
{
    g_autoptr(qemuMigrationParams) params = NULL;

    params = g_new0(qemuMigrationParams, 1);

    params->caps = virBitmapNew(QEMU_MIGRATION_CAP_LAST);

    return g_steal_pointer(&params);
}


void
qemuMigrationParamsFree(qemuMigrationParams *migParams)
{
    size_t i;

    if (!migParams)
        return;

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        if (qemuMigrationParamInfo[i].type == QEMU_MIGRATION_PARAM_TYPE_STRING)
            g_free(migParams->params[i].value.s);
    }

    virBitmapFree(migParams->caps);
    virJSONValueFree(migParams->blockDirtyBitmapMapping);
    g_free(migParams);
}


static int
qemuMigrationParamsCheckType(qemuMigrationParam param,
                             qemuMigrationParamType type)
{
    if (qemuMigrationParamInfo[param].type != type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Type mismatch for '%1$s' migration parameter"),
                       qemuMigrationParamTypeToString(param));
        return -1;
    }

    return 0;
}


static int
qemuMigrationParamsGetTPInt(qemuMigrationParams *migParams,
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
                           _("migration parameter '%1$s' must be less than %2$u"),
                           name, max + 1);
            return -1;
        }
        migParams->params[param].value.i *= unit;
    }

    migParams->params[param].set = !!rc;
    return 0;
}


static int
qemuMigrationParamsSetTPInt(qemuMigrationParams *migParams,
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
qemuMigrationParamsGetTPULL(qemuMigrationParams *migParams,
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
                           _("migration parameter '%1$s' must be less than %2$llu"),
                           name, max + 1);
            return -1;
        }
        migParams->params[param].value.ull *= unit;
    }

    migParams->params[param].set = !!rc;
    return 0;
}


static int
qemuMigrationParamsSetTPULL(qemuMigrationParams *migParams,
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
qemuMigrationParamsGetTPString(qemuMigrationParams *migParams,
                               qemuMigrationParam param,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *name)
{
    const char *value = NULL;
    int rc;

    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_STRING) < 0)
        return -1;

    if (!params)
        return 0;

    if ((rc = virTypedParamsGetString(params, nparams, name, &value)) < 0)
        return -1;

    migParams->params[param].value.s = g_strdup(value);
    migParams->params[param].set = !!rc;
    return 0;
}


static int
qemuMigrationParamsSetTPString(qemuMigrationParams *migParams,
                               qemuMigrationParam param,
                               virTypedParameterPtr *params,
                               int *nparams,
                               int *maxparams,
                               const char *name)
{
    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_STRING) < 0)
        return -1;

    if (!migParams->params[param].set)
        return 0;

    return virTypedParamsAddString(params, nparams, maxparams, name,
                                   migParams->params[param].value.s);
}



static int
qemuMigrationParamsSetCompression(virTypedParameterPtr params,
                                  int nparams,
                                  unsigned int flags,
                                  qemuMigrationParams *migParams)
{
    size_t i;
    int method;

    for (i = 0; i < nparams; i++) {
        if (STRNEQ(params[i].field, VIR_MIGRATE_PARAM_COMPRESSION))
            continue;

        method = qemuMigrationCompressMethodTypeFromString(params[i].value.s);
        if (method < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported compression method '%1$s'"),
                           params[i].value.s);
            return -1;
        }

        if (migParams->compMethods & (1ULL << method)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Compression method '%1$s' is specified twice"),
                           params[i].value.s);
            return -1;
        }

        if ((method == QEMU_MIGRATION_COMPRESS_MT ||
             method == QEMU_MIGRATION_COMPRESS_XBZRLE) &&
            flags & VIR_MIGRATE_PARALLEL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Compression method '%1$s' isn't supported with parallel migration"),
                           params[i].value.s);
            return -1;
        }

        if ((method == QEMU_MIGRATION_COMPRESS_ZLIB ||
             method == QEMU_MIGRATION_COMPRESS_ZSTD) &&
            !(flags & VIR_MIGRATE_PARALLEL)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Compression method '%1$s' is only supported with parallel migration"),
                           params[i].value.s);
            return -1;
        }

        if (migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_COMPRESSION].set) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Only one compression method could be specified with parallel compression"));
            return -1;
        }

        migParams->compMethods |= 1ULL << method;

        switch ((qemuMigrationCompressMethod) method) {
        case QEMU_MIGRATION_COMPRESS_XBZRLE:
            ignore_value(virBitmapSetBit(migParams->caps, QEMU_MIGRATION_CAP_XBZRLE));
            break;

        case QEMU_MIGRATION_COMPRESS_MT:
            ignore_value(virBitmapSetBit(migParams->caps, QEMU_MIGRATION_CAP_COMPRESS));
            break;

        case QEMU_MIGRATION_COMPRESS_ZLIB:
        case QEMU_MIGRATION_COMPRESS_ZSTD:
            migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_COMPRESSION].value.s = g_strdup(params[i].value.s);
            migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_COMPRESSION].set = true;
            break;

        case QEMU_MIGRATION_COMPRESS_LAST:
        default:
            break;
        }
    }

    if ((migParams->params[QEMU_MIGRATION_PARAM_COMPRESS_LEVEL].set ||
         migParams->params[QEMU_MIGRATION_PARAM_COMPRESS_THREADS].set ||
         migParams->params[QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS].set) &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_MT))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn multithread compression on to tune it"));
        return -1;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE].set &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn xbzrle compression on to tune it"));
        return -1;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_ZLIB_LEVEL].set &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_ZLIB))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn zlib compression on to tune it"));
        return -1;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_ZSTD_LEVEL].set &&
        !(migParams->compMethods & (1ULL << QEMU_MIGRATION_COMPRESS_ZSTD))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn zstd compression on to tune it"));
        return -1;
    }

    if (!migParams->compMethods && (flags & VIR_MIGRATE_COMPRESSED)) {
        if (flags & VIR_MIGRATE_PARALLEL) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("No compression algorithm selected for parallel migration"));
            return -1;
        }

        migParams->compMethods = 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE;
        ignore_value(virBitmapSetBit(migParams->caps,
                                     QEMU_MIGRATION_CAP_XBZRLE));
    }

    return 0;
}


void
qemuMigrationParamsSetBlockDirtyBitmapMapping(qemuMigrationParams *migParams,
                                              virJSONValue **params)
{
    virJSONValueFree(migParams->blockDirtyBitmapMapping);
    migParams->blockDirtyBitmapMapping = g_steal_pointer(params);

    if (migParams->blockDirtyBitmapMapping)
        ignore_value(virBitmapSetBit(migParams->caps, QEMU_MIGRATION_CAP_BLOCK_DIRTY_BITMAPS));
    else
        ignore_value(virBitmapClearBit(migParams->caps, QEMU_MIGRATION_CAP_BLOCK_DIRTY_BITMAPS));
}


qemuMigrationParams *
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags,
                             qemuMigrationParty party)
{
    g_autoptr(qemuMigrationParams) migParams = NULL;
    size_t i;

    if (!(migParams = qemuMigrationParamsNew()))
        return NULL;

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsFlagMap); i++) {
        const qemuMigrationParamsFlagMapItem *item = &qemuMigrationParamsFlagMap[i];
        int match = 0;

        if (item->match == QEMU_MIGRATION_FLAG_REQUIRED)
            match = item->flag;

        if (item->party & party && (flags & item->flag) == match) {
            VIR_DEBUG("Enabling migration capability '%s'",
                      qemuMigrationCapabilityTypeToString(item->cap));
            ignore_value(virBitmapSetBit(migParams->caps, item->cap));
        }
    }

    for (i = 0; i < G_N_ELEMENTS(qemuMigrationParamsTPMap); i++) {
        const qemuMigrationParamsTPMapItem *item = &qemuMigrationParamsTPMap[i];

        if (!(item->party & party))
            continue;

        VIR_DEBUG("Setting migration parameter '%s' from '%s'",
                  qemuMigrationParamTypeToString(item->param), item->typedParam);

        switch (qemuMigrationParamInfo[item->param].type) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            if (qemuMigrationParamsGetTPInt(migParams, item->param, params,
                                            nparams, item->typedParam,
                                            item->unit) < 0)
                return NULL;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            if (qemuMigrationParamsGetTPULL(migParams, item->param, params,
                                            nparams, item->typedParam,
                                            item->unit) < 0)
                return NULL;
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            if (qemuMigrationParamsGetTPString(migParams, item->param, params,
                                               nparams, item->typedParam) < 0)
                return NULL;
            break;
        }
    }

    if ((migParams->params[QEMU_MIGRATION_PARAM_THROTTLE_INITIAL].set ||
         migParams->params[QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT].set) &&
        !(flags & VIR_MIGRATE_AUTO_CONVERGE)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn auto convergence on to tune it"));
        return NULL;
    }

    if (migParams->params[QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS].set &&
        !(flags & VIR_MIGRATE_PARALLEL)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn parallel migration on to tune it"));
        return NULL;
    }

    if (qemuMigrationParamsSetCompression(params, nparams, flags, migParams) < 0)
        return NULL;

    return g_steal_pointer(&migParams);
}


int
qemuMigrationParamsDump(qemuMigrationParams *migParams,
                        virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        unsigned int *flags)
{
    size_t i;

    if (migParams->compMethods == 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE &&
        !migParams->params[QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE].set) {
        *flags |= VIR_MIGRATE_COMPRESSED;
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

        switch (qemuMigrationParamInfo[item->param].type) {
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
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            if (qemuMigrationParamsSetTPString(migParams, item->param,
                                               params, nparams, maxparams,
                                               item->typedParam) < 0)
                return -1;
            break;
        }
    }

    return 0;
}


qemuMigrationParams *
qemuMigrationParamsFromJSON(virJSONValue *params)
{
    g_autoptr(qemuMigrationParams) migParams = NULL;
    qemuMigrationParamValue *pv;
    const char *name;
    const char *str;
    size_t i;

    if (!(migParams = qemuMigrationParamsNew()))
        return NULL;

    if (!params)
        return g_steal_pointer(&migParams);

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        name = qemuMigrationParamTypeToString(i);
        pv = &migParams->params[i];

        switch (qemuMigrationParamInfo[i].type) {
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
                pv->value.s = g_strdup(str);
                pv->set = true;
            }
            break;
        }
    }

    return g_steal_pointer(&migParams);
}


virJSONValue *
qemuMigrationParamsToJSON(qemuMigrationParams *migParams,
                          bool postcopyResume)
{
    g_autoptr(virJSONValue) params = virJSONValueNewObject();
    size_t i;

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        const char *name = qemuMigrationParamTypeToString(i);
        qemuMigrationParamValue *pv = &migParams->params[i];
        int rc = 0;

        if (!pv->set)
            continue;

        if (postcopyResume && !qemuMigrationParamInfo[i].applyOnPostcopyResume)
            continue;

        switch (qemuMigrationParamInfo[i].type) {
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
            return NULL;
    }

    if (migParams->blockDirtyBitmapMapping) {
        g_autoptr(virJSONValue) mapping = virJSONValueCopy(migParams->blockDirtyBitmapMapping);

        if (!mapping)
            return NULL;

        if (virJSONValueObjectAppend(params, "block-bitmap-mapping", &mapping) < 0)
            return NULL;
    }

    return g_steal_pointer(&params);
}


virJSONValue *
qemuMigrationCapsToJSON(virBitmap *caps,
                        virBitmap *states)
{
    g_autoptr(virJSONValue) json = virJSONValueNewArray();
    qemuMigrationCapability bit;

    for (bit = 0; bit < QEMU_MIGRATION_CAP_LAST; bit++) {
        g_autoptr(virJSONValue) cap = NULL;

        if (!virBitmapIsBitSet(caps, bit))
            continue;

        if (virJSONValueObjectAdd(&cap,
                                  "s:capability", qemuMigrationCapabilityTypeToString(bit),
                                  "b:state", virBitmapIsBitSet(states, bit),
                                  NULL) < 0)
            return NULL;

        if (virJSONValueArrayAppend(json, &cap) < 0)
            return NULL;
    }

    return g_steal_pointer(&json);
}


static int
qemuMigrationParamsApplyCaps(virDomainObj *vm,
                             virBitmap *states)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) json = NULL;

    if (!(json = qemuMigrationCapsToJSON(priv->migrationCaps, states)))
        return -1;

    if (virJSONValueArraySize(json) > 0 &&
        qemuMonitorSetMigrationCapabilities(priv->mon, &json) < 0)
        return -1;

    return 0;
}


static int
qemuMigrationParamsApplyValues(virDomainObj *vm,
                               qemuMigrationParams *params,
                               bool postcopyResume)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) json = NULL;

    if (!(json = qemuMigrationParamsToJSON(params, postcopyResume)))
        return -1;

    if (virJSONValueObjectKeysNumber(json) > 0 &&
        qemuMonitorSetMigrationParams(priv->mon, &json) < 0)
        return -1;

    return 0;
}


/**
 * qemuMigrationParamsApply
 * @driver: qemu driver
 * @vm: domain object
 * @asyncJob: migration job
 * @migParams: migration parameters to send to QEMU
 * @apiFlags: migration flags, some of them may affect which parameters are applied
 *
 * Send parameters stored in @migParams to QEMU. If @apiFlags is non-zero, some
 * parameters that do not make sense for the enabled flags will be ignored.
 * VIR_MIGRATE_POSTCOPY_RESUME is the only flag checked currently.
 *
 * Returns 0 on success, -1 on failure.
 */
int
qemuMigrationParamsApply(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *migParams,
                         unsigned int apiFlags)
{
    bool postcopyResume = !!(apiFlags & VIR_MIGRATE_POSTCOPY_RESUME);
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    /* Changing capabilities is only allowed before migration starts, we need
     * to skip them when resuming post-copy migration.
     */
    if (!postcopyResume) {
        if (asyncJob == VIR_ASYNC_JOB_NONE) {
            if (!virBitmapIsAllClear(migParams->caps)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Migration capabilities can only be set by a migration job"));
                goto cleanup;
            }
        } else if (qemuMigrationParamsApplyCaps(vm, migParams->caps) < 0) {
            goto cleanup;
        }
    }

    if (qemuMigrationParamsApplyValues(vm, migParams, postcopyResume) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuDomainObjExitMonitor(vm);

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
qemuMigrationParamsSetString(qemuMigrationParams *migParams,
                             qemuMigrationParam param,
                             const char *value)
{
    if (qemuMigrationParamsCheckType(param, QEMU_MIGRATION_PARAM_TYPE_STRING) < 0)
        return -1;

    migParams->params[param].value.s = g_strdup(value);

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
qemuMigrationParamsEnableTLS(virQEMUDriver *driver,
                             virDomainObj *vm,
                             bool tlsListen,
                             int asyncJob,
                             char **tlsAlias,
                             const char *hostname,
                             qemuMigrationParams *migParams)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    g_autoptr(virJSONValue) tlsProps = NULL;
    g_autoptr(virJSONValue) secProps = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *secAlias = NULL;

    if (!cfg->migrateTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("host migration TLS directory not configured"));
        return -1;
    }

    if (!jobPriv->migParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TLS migration is not supported with this QEMU binary"));
        return -1;
    }

    /* If there's a secret, then grab/store it now using the connection */
    if (cfg->migrateTLSx509secretUUID) {
        if (!(priv->migSecinfo =
              qemuDomainSecretInfoTLSNew(priv, QEMU_MIGRATION_TLS_ALIAS_BASE,
                                         cfg->migrateTLSx509secretUUID)))
            return -1;
        secAlias = priv->migSecinfo->alias;
    }

    if (!(*tlsAlias = qemuAliasTLSObjFromSrcAlias(QEMU_MIGRATION_TLS_ALIAS_BASE)))
        return -1;

    if (qemuDomainGetTLSObjects(priv->migSecinfo,
                                cfg->migrateTLSx509certdir, tlsListen,
                                cfg->migrateTLSx509verify,
                                *tlsAlias, &tlsProps, &secProps) < 0)
        return -1;

    /* Ensure the domain doesn't already have the TLS objects defined...
     * This should prevent any issues just in case some cleanup wasn't
     * properly completed (both src and dst use the same alias) or
     * some other error path between now and perform . */
    qemuDomainDelTLSObjects(vm, asyncJob, secAlias, *tlsAlias);

    if (qemuDomainAddTLSObjects(vm, asyncJob, &secProps, &tlsProps) < 0)
        return -1;

    if (qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_CREDS,
                                     *tlsAlias) < 0)
        return -1;

    if (!migParams->params[QEMU_MIGRATION_PARAM_TLS_HOSTNAME].set &&
        qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_HOSTNAME,
                                     NULLSTR_EMPTY(hostname)) < 0)
        return -1;

    return 0;
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
qemuMigrationParamsDisableTLS(virDomainObj *vm,
                              qemuMigrationParams *migParams)
{
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;

    if (!jobPriv->migParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set)
        return 0;

    if (qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_CREDS, "") < 0 ||
        qemuMigrationParamsSetString(migParams,
                                     QEMU_MIGRATION_PARAM_TLS_HOSTNAME, "") < 0)
        return -1;

    return 0;
}


bool
qemuMigrationParamsTLSHostnameIsSet(qemuMigrationParams *migParams)
{
    int param = QEMU_MIGRATION_PARAM_TLS_HOSTNAME;
    return (migParams->params[param].set &&
            STRNEQ(migParams->params[param].value.s, ""));
}


/* qemuMigrationParamsResetTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 * @apiFlags: API flags used to start the migration
 *
 * Deconstruct all the setup possibly done for TLS - delete the TLS and
 * security objects and free the secinfo
 */
static void
qemuMigrationParamsResetTLS(virDomainObj *vm,
                            int asyncJob,
                            qemuMigrationParams *origParams,
                            unsigned int apiFlags)
{
    g_autofree char *tlsAlias = NULL;
    g_autofree char *secAlias = NULL;

    /* There's nothing to do if QEMU does not support TLS migration or we were
     * not asked to enable it. */
    if (!origParams->params[QEMU_MIGRATION_PARAM_TLS_CREDS].set ||
        !(apiFlags & VIR_MIGRATE_TLS))
        return;

    tlsAlias = qemuAliasTLSObjFromSrcAlias(QEMU_MIGRATION_TLS_ALIAS_BASE);
    secAlias = qemuAliasForSecret(QEMU_MIGRATION_TLS_ALIAS_BASE, NULL, 0);

    qemuDomainDelTLSObjects(vm, asyncJob, secAlias, tlsAlias);
    g_clear_pointer(&QEMU_DOMAIN_PRIVATE(vm)->migSecinfo, qemuDomainSecretInfoFree);
}


int
qemuMigrationParamsFetch(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams **migParams)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) jsonParams = NULL;
    int rc;

    *migParams = NULL;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetMigrationParams(priv->mon, &jsonParams);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    if (!(*migParams = qemuMigrationParamsFromJSON(jsonParams)))
        return -1;

    return 0;
}


int
qemuMigrationParamsSetULL(qemuMigrationParams *migParams,
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
qemuMigrationParamsGetULL(qemuMigrationParams *migParams,
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
 * virDomainJobObj so that we can properly reset them at the end of migration.
 * Reports an error if any of the currently used capabilities in @migParams
 * are unsupported by QEMU.
 */
int
qemuMigrationParamsCheck(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *migParams,
                         virBitmap *remoteCaps)
{
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    qemuMigrationCapability cap;
    qemuMigrationParty party;
    size_t i;

    if (asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT)
        party = QEMU_MIGRATION_SOURCE;
    else
        party = QEMU_MIGRATION_DESTINATION;

    for (cap = 0; cap < QEMU_MIGRATION_CAP_LAST; cap++) {
        bool state = false;

        ignore_value(virBitmapGetBit(migParams->caps, cap, &state));

        if (state && !qemuMigrationCapsGet(vm, cap)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("Migration option '%1$s' is not supported by QEMU binary"),
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

    return qemuMigrationParamsFetch(vm, asyncJob, &jobPriv->migParams);
}


/*
 * qemuMigrationParamsReset:
 *
 * Reset all migration parameters so that the next job which internally uses
 * migration (save, managedsave, snapshots, dump) will not try to use them.
 */
void
qemuMigrationParamsReset(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *origParams,
                         unsigned int apiFlags)
{
    virErrorPtr err;
    g_autoptr(virBitmap) clearCaps = NULL;
    int rc;

    virErrorPreserveLast(&err);

    VIR_DEBUG("Resetting migration parameters %p, flags 0x%x",
              origParams, apiFlags);

    if (!virDomainObjIsActive(vm) || !origParams)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    clearCaps = virBitmapNew(0);

    rc = 0;
    if (qemuMigrationParamsApplyCaps(vm, clearCaps) < 0 ||
        qemuMigrationParamsApplyValues(vm, origParams, false) < 0)
        rc = -1;

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    qemuMigrationParamsResetTLS(vm, asyncJob, origParams, apiFlags);

 cleanup:
    virErrorRestore(&err);
}


void
qemuMigrationParamsFormat(virBuffer *buf,
                          qemuMigrationParams *migParams)
{
    qemuMigrationParamValue *pv;
    size_t i;

    virBufferAddLit(buf, "<migParams>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < QEMU_MIGRATION_PARAM_LAST; i++) {
        pv = &migParams->params[i];

        if (!pv->set)
            continue;

        virBufferAsprintf(buf, "<param name='%s' ",
                          qemuMigrationParamTypeToString(i));

        switch (qemuMigrationParamInfo[i].type) {
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
                         qemuMigrationParams **migParams)
{
    g_autoptr(qemuMigrationParams) params = NULL;
    qemuMigrationParamValue *pv;
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int rc;
    int n;

    *migParams = NULL;

    if ((rc = virXPathBoolean("boolean(./migParams)", ctxt)) < 0)
        return -1;

    if (rc == 0)
        return 0;

    if ((n = virXPathNodeSet("./migParams[1]/param", ctxt, &nodes)) < 0)
        return -1;

    if (!(params = qemuMigrationParamsNew()))
        return -1;

    for (i = 0; i < n; i++) {
        g_autofree char *name = NULL;
        g_autofree char *value = NULL;
        int param;

        if (!(name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing migration parameter name"));
            return -1;
        }

        if ((param = qemuMigrationParamTypeFromString(name)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown migration parameter '%1$s'"), name);
            return -1;
        }
        pv = &params->params[param];

        if (!(value = virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing value for migration parameter '%1$s'"),
                           name);
            return -1;
        }

        rc = 0;
        switch (qemuMigrationParamInfo[param].type) {
        case QEMU_MIGRATION_PARAM_TYPE_INT:
            rc = virStrToLong_i(value, NULL, 10, &pv->value.i);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_ULL:
            rc = virStrToLong_ullp(value, NULL, 10, &pv->value.ull);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_BOOL:
            rc = virStringParseYesNo(value, &pv->value.b);
            break;

        case QEMU_MIGRATION_PARAM_TYPE_STRING:
            pv->value.s = g_steal_pointer(&value);
            break;
        }

        if (rc < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid value '%1$s' for migration parameter '%2$s'"),
                           value, name);
            return -1;
        }

        pv->set = true;
    }

    *migParams = g_steal_pointer(&params);

    return 0;
}


int
qemuMigrationCapsCheck(virDomainObj *vm,
                       int asyncJob,
                       bool reconnect)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) json = NULL;
    g_auto(GStrv) caps = NULL;
    char **capStr;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetMigrationCapabilities(priv->mon, &caps);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    if (!caps)
        return 0;

    priv->migrationCaps = virBitmapNew(QEMU_MIGRATION_CAP_LAST);

    for (capStr = caps; *capStr; capStr++) {
        int cap = qemuMigrationCapabilityTypeFromString(*capStr);

        if (cap < 0) {
            VIR_DEBUG("Unknown migration capability: '%s'", *capStr);
        } else {
            ignore_value(virBitmapSetBit(priv->migrationCaps, cap));
            VIR_DEBUG("Found migration capability: '%s'", *capStr);
        }
    }

    if (!reconnect) {
        g_autoptr(virBitmap) migEvent = virBitmapNew(QEMU_MIGRATION_CAP_LAST);

        ignore_value(virBitmapSetBit(migEvent, QEMU_MIGRATION_CAP_EVENTS));

        if (!(json = qemuMigrationCapsToJSON(migEvent, migEvent)))
            return -1;

        if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
            return -1;

        rc = qemuMonitorSetMigrationCapabilities(priv->mon, &json);

        qemuDomainObjExitMonitor(vm);

        if (rc < 0)
            return -1;
    }

    /* Migration events capability must always be enabled, clearing it from
     * migration capabilities bitmap makes sure it won't be touched anywhere
     * else.
     */
    ignore_value(virBitmapClearBit(priv->migrationCaps,
                                   QEMU_MIGRATION_CAP_EVENTS));

    return 0;
}


bool
qemuMigrationCapsGet(virDomainObj *vm,
                     qemuMigrationCapability cap)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    bool enabled = false;

    if (priv->migrationCaps)
        ignore_value(virBitmapGetBit(priv->migrationCaps, cap, &enabled));

    return enabled;
}


/**
 * qemuMigrationParamsGetTLSHostname:
 * @migParams: Migration params object
 *
 * Fetches the value of the QEMU_MIGRATION_PARAM_TLS_HOSTNAME parameter which is
 * passed from the user as VIR_MIGRATE_PARAM_TLS_DESTINATION
 */
const char *
qemuMigrationParamsGetTLSHostname(qemuMigrationParams *migParams)
{
    if (!migParams->params[QEMU_MIGRATION_PARAM_TLS_HOSTNAME].set)
        return NULL;

    return migParams->params[QEMU_MIGRATION_PARAM_TLS_HOSTNAME].value.s;
}
