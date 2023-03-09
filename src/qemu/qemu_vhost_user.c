/*
 * qemu_vhost_user.c: QEMU vhost-user
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "qemu_vhost_user.h"
#include "qemu_interop_config.h"
#include "virjson.h"
#include "virlog.h"
#include "viralloc.h"
#include "virenum.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_vhost_user");

typedef enum {
    QEMU_VHOST_USER_TYPE_NONE = 0,
    QEMU_VHOST_USER_TYPE_9P,
    QEMU_VHOST_USER_TYPE_BALLOON,
    QEMU_VHOST_USER_TYPE_BLOCK,
    QEMU_VHOST_USER_TYPE_CAIF,
    QEMU_VHOST_USER_TYPE_CONSOLE,
    QEMU_VHOST_USER_TYPE_CRYPTO,
    QEMU_VHOST_USER_TYPE_GPU,
    QEMU_VHOST_USER_TYPE_INPUT,
    QEMU_VHOST_USER_TYPE_NET,
    QEMU_VHOST_USER_TYPE_RNG,
    QEMU_VHOST_USER_TYPE_RPMSG,
    QEMU_VHOST_USER_TYPE_RPROC_SERIAL,
    QEMU_VHOST_USER_TYPE_SCSI,
    QEMU_VHOST_USER_TYPE_VSOCK,
    QEMU_VHOST_USER_TYPE_FS,

    QEMU_VHOST_USER_TYPE_LAST
} qemuVhostUserType;

VIR_ENUM_DECL(qemuVhostUserType);
VIR_ENUM_IMPL(qemuVhostUserType,
              QEMU_VHOST_USER_TYPE_LAST,
              "",
              "9p",
              "balloon",
              "block",
              "caif",
              "console",
              "crypto",
              "gpu",
              "input",
              "net",
              "rng",
              "rpmsg",
              "rproc-serial",
              "scsi",
              "vsock",
              "fs",
);

typedef enum {
    QEMU_VHOST_USER_GPU_FEATURE_NONE = 0,
    QEMU_VHOST_USER_GPU_FEATURE_VIRGL,
    QEMU_VHOST_USER_GPU_FEATURE_RENDER_NODE,

    QEMU_VHOST_USER_GPU_FEATURE_LAST
} qemuVhostUserGPUFeature;

VIR_ENUM_DECL(qemuVhostUserGPUFeature);
VIR_ENUM_IMPL(qemuVhostUserGPUFeature,
              QEMU_VHOST_USER_GPU_FEATURE_LAST,
              "",
              "virgl",
              "render-node",
);

typedef struct _qemuVhostUserGPU qemuVhostUserGPU;
struct _qemuVhostUserGPU {
    size_t nfeatures;
    qemuVhostUserGPUFeature *features;
};

struct _qemuVhostUser {
    /* Description intentionally not parsed. */
    qemuVhostUserType type;
    char *binary;
    /* Tags intentionally not parsed. */

    union {
        qemuVhostUserGPU gpu;
    } capabilities;
};


static void
qemuVhostUserGPUFeatureFree(qemuVhostUserGPUFeature *features)
{
    g_free(features);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuVhostUserGPUFeature, qemuVhostUserGPUFeatureFree);


void
qemuVhostUserFree(qemuVhostUser *vu)
{
    if (!vu)
        return;

    if (vu->type == QEMU_VHOST_USER_TYPE_GPU)
        g_free(vu->capabilities.gpu.features);

    g_free(vu->binary);

    g_free(vu);
}


/* 1MiB should be enough for everybody (TM) */
#define DOCUMENT_SIZE (1024 * 1024)


static int
qemuVhostUserTypeParse(const char *path,
                       virJSONValue *doc,
                       qemuVhostUser *vu)
{
    const char *type = virJSONValueObjectGetString(doc, "type");
    int tmp;

    VIR_DEBUG("vhost-user description path '%s' type : %s",
              path, type);

    if ((tmp = qemuVhostUserTypeTypeFromString(type)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown vhost-user type: '%1$s'"),
                       type);
        return -1;
    }

    vu->type = tmp;

    return 0;
}


static int
qemuVhostUserBinaryParse(const char *path,
                         virJSONValue *doc,
                         qemuVhostUser *vu)
{
    const char *binary = virJSONValueObjectGetString(doc, "binary");

    VIR_DEBUG("vhost-user description path '%s' binary : %s",
              path, binary);

    vu->binary = g_strdup(binary);

    return 0;
}


qemuVhostUser *
qemuVhostUserParse(const char *path)
{
    g_autofree char *cont = NULL;
    g_autoptr(virJSONValue) doc = NULL;
    g_autoptr(qemuVhostUser) vu = NULL;

    if (virFileReadAll(path, DOCUMENT_SIZE, &cont) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(cont))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json file '%1$s'"),
                       path);
        return NULL;
    }

    vu = g_new0(qemuVhostUser, 1);

    if (qemuVhostUserTypeParse(path, doc, vu) < 0)
        return NULL;

    if (qemuVhostUserBinaryParse(path, doc, vu) < 0)
        return NULL;

    return g_steal_pointer(&vu);
}


char *
qemuVhostUserFormat(qemuVhostUser *vu)
{
    g_autoptr(virJSONValue) doc = NULL;

    if (!vu)
        return NULL;

    doc = virJSONValueNewObject();

    if (virJSONValueObjectAppendString(doc, "type",
                                       qemuVhostUserTypeTypeToString(vu->type)) < 0)
        return NULL;

    if (virJSONValueObjectAppendString(doc, "binary", vu->binary) < 0)
        return NULL;

    return virJSONValueToString(doc, true);
}


int
qemuVhostUserFetchConfigs(char ***configs,
                          bool privileged)
{
    return qemuInteropFetchConfigs("vhost-user", configs, privileged);
}


static ssize_t
qemuVhostUserFetchParsedConfigs(bool privileged,
                                qemuVhostUser ***vhostuserRet,
                                char ***pathsRet)
{
    g_auto(GStrv) paths = NULL;
    size_t npaths;
    qemuVhostUser **vus = NULL;
    size_t i;

    if (qemuVhostUserFetchConfigs(&paths, privileged) < 0)
        return -1;

    if (!paths)
        return 0;

    npaths = g_strv_length(paths);
    vus = g_new0(qemuVhostUser *, npaths);

    for (i = 0; i < npaths; i++) {
        if (!(vus[i] = qemuVhostUserParse(paths[i])))
            goto error;
    }

    *vhostuserRet = g_steal_pointer(&vus);
    if (pathsRet)
        *pathsRet = g_steal_pointer(&paths);
    return npaths;

 error:
    while (i > 0)
        qemuVhostUserFree(vus[--i]);
    VIR_FREE(vus);
    return -1;
}


static int
qemuVhostUserGPUFillCapabilities(qemuVhostUser *vu,
                                 virJSONValue *doc)
{
    qemuVhostUserGPU *gpu = &vu->capabilities.gpu;
    virJSONValue *featuresJSON;
    size_t nfeatures;
    size_t nparsed = 0;
    size_t i;
    g_autoptr(qemuVhostUserGPUFeature) features = NULL;

    if (!(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get features from '%1$s'"),
                       vu->binary);
        return -1;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);
    features = g_new0(qemuVhostUserGPUFeature, nfeatures);

    for (i = 0; i < nfeatures; i++) {
        virJSONValue *item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuVhostUserGPUFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_DEBUG("ignoring unknown QEMU vhost-user feature '%s'", tmpStr);
            continue;
        }

        features[nparsed] = tmp;
        nparsed++;
    }

    gpu->features = g_steal_pointer(&features);
    gpu->nfeatures = nparsed;

    return 0;
}


static bool
qemuVhostUserGPUHasFeature(qemuVhostUserGPU *gpu,
                           qemuVhostUserGPUFeature feature)
{
    size_t i;

    for (i = 0; i < gpu->nfeatures; i++) {
        if (gpu->features[i] == feature)
            return true;
    }

    return false;
}


int
qemuVhostUserFillDomainGPU(virQEMUDriver *driver,
                           virDomainVideoDef *video)
{
    qemuVhostUser **vus = NULL;
    qemuVhostUser *vu = NULL;
    ssize_t nvus = 0;
    ssize_t i;
    int ret = -1;

    if ((nvus = qemuVhostUserFetchParsedConfigs(driver->privileged,
                                                &vus, NULL)) < 0)
        goto end;

    for (i = 0; i < nvus; i++) {
        g_autoptr(virJSONValue) doc = NULL;
        g_autofree char *output = NULL;
        g_autoptr(virCommand) cmd = NULL;

        vu = vus[i];
        if (vu->type != QEMU_VHOST_USER_TYPE_GPU)
            continue;

        cmd = virCommandNewArgList(vu->binary, "--print-capabilities", NULL);
        virCommandSetOutputBuffer(cmd, &output);
        if (virCommandRun(cmd, NULL) < 0)
            continue;

        if (!(doc = virJSONValueFromString(output))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse json capabilities '%1$s'"),
                           vu->binary);
            continue;
        }

        if (qemuVhostUserGPUFillCapabilities(vu, doc) < 0)
            continue;

        if (video->accel) {
            if (video->accel->accel3d &&
                !qemuVhostUserGPUHasFeature(&vu->capabilities.gpu,
                                            QEMU_VHOST_USER_GPU_FEATURE_VIRGL))
                continue;

            if (video->accel->rendernode &&
                !qemuVhostUserGPUHasFeature(&vu->capabilities.gpu,
                                            QEMU_VHOST_USER_GPU_FEATURE_RENDER_NODE))
                continue;
        }

        if (!video->driver)
            video->driver = g_new0(virDomainVideoDriverDef, 1);

        VIR_FREE(video->driver->vhost_user_binary);
        video->driver->vhost_user_binary = g_strdup(vu->binary);

        break;
    }

    if (i == nvus) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Unable to find a satisfying vhost-user-gpu"));
        goto end;
    }

    if (!video->accel)
        video->accel = g_new0(virDomainVideoAccelDef, 1);

    if (!video->accel->rendernode &&
        qemuVhostUserGPUHasFeature(&vu->capabilities.gpu,
                                   QEMU_VHOST_USER_GPU_FEATURE_RENDER_NODE)) {
        video->accel->rendernode = virHostGetDRMRenderNode();
        if (!video->accel->rendernode)
            goto end;
    }

    ret = 0;

 end:
    for (i = 0; i < nvus; i++)
        qemuVhostUserFree(vus[i]);
    VIR_FREE(vus);
    return ret;
}


int
qemuVhostUserFillDomainFS(virQEMUDriver *driver,
                          virDomainFSDef *fs)
{
    qemuVhostUser **vus = NULL;
    ssize_t nvus = 0;
    ssize_t i;
    int ret = -1;

    if ((nvus = qemuVhostUserFetchParsedConfigs(driver->privileged,
                                                &vus, NULL)) < 0)
        goto end;

    for (i = 0; i < nvus; i++) {
        qemuVhostUser *vu = vus[i];

        if (vu->type != QEMU_VHOST_USER_TYPE_FS)
            continue;

        fs->binary = g_strdup(vu->binary);
        break;
    }

    if (i == nvus) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Unable to find a satisfying virtiofsd"));
        goto end;
    }

    ret = 0;

 end:
    for (i = 0; i < nvus; i++)
        qemuVhostUserFree(vus[i]);
    g_free(vus);
    return ret;
}
