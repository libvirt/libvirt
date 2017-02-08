/*
 * vz_sdk.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Parallels, Inc.
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
#include <stdarg.h>

#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"
#include "nodeinfo.h"
#include "virlog.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virtime.h"
#include "virhostcpu.h"

#include "storage/storage_driver.h"
#include "vz_sdk.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS
#define JOB_INFINIT_WAIT_TIMEOUT UINT_MAX

static int
prlsdkUUIDParse(const char *uuidstr, unsigned char *uuid);
static void
prlsdkConvertError(PRL_RESULT pret);

VIR_LOG_INIT("parallels.sdk");

static PRL_HANDLE
prlsdkFindNetByMAC(PRL_HANDLE sdkdom, virMacAddrPtr mac);
static PRL_HANDLE
prlsdkGetDisk(PRL_HANDLE sdkdom, virDomainDiskDefPtr disk);
static bool
prlsdkInBootList(PRL_HANDLE sdkdom,
                 PRL_HANDLE sdktargetdev);

/*
 * Log error description
 */
static void
logPrlErrorHelper(PRL_RESULT err, const char *filename,
                  const char *funcname, size_t linenr)
{
    char *msg1 = NULL, *msg2 = NULL;
    PRL_UINT32 len = 0;

    /* Get required buffer length */
    PrlApi_GetResultDescription(err, PRL_TRUE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg1, len) < 0)
        goto cleanup;

    /* get short error description */
    PrlApi_GetResultDescription(err, PRL_TRUE, PRL_FALSE, msg1, &len);

    PrlApi_GetResultDescription(err, PRL_FALSE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg2, len) < 0)
        goto cleanup;

    /* get long error description */
    PrlApi_GetResultDescription(err, PRL_FALSE, PRL_FALSE, msg2, &len);

    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INTERNAL_ERROR,
                         filename, funcname, linenr,
                         _("%s %s"), msg1, msg2);

 cleanup:
    VIR_FREE(msg1);
    VIR_FREE(msg2);
}

#define logPrlError(code)                          \
    logPrlErrorHelper(code, __FILE__,              \
                      __FUNCTION__, __LINE__)

#define prlsdkCheckRetGoto(ret, label)             \
    do {                                           \
        if (PRL_FAILED(ret)) {                     \
            logPrlError(ret);                      \
            goto label;                            \
        }                                          \
    } while (0)

#define prlsdkCheckRetExit(ret, code)              \
    do {                                           \
        if (PRL_FAILED(ret)) {                     \
            logPrlError(ret);                      \
            return code;                           \
        }                                          \
    } while (0)

static void
logPrlEventErrorHelper(PRL_HANDLE event, const char *filename,
                       const char *funcname, size_t linenr)
{
    char *msg1 = NULL, *msg2 = NULL;
    PRL_UINT32 len = 0;

    PrlEvent_GetErrString(event, PRL_TRUE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg1, len) < 0)
        goto cleanup;

    PrlEvent_GetErrString(event, PRL_TRUE, PRL_FALSE, msg1, &len);

    PrlEvent_GetErrString(event, PRL_FALSE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg2, len) < 0)
        goto cleanup;

    PrlEvent_GetErrString(event, PRL_FALSE, PRL_FALSE, msg2, &len);

    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INTERNAL_ERROR,
                         filename, funcname, linenr,
                         _("%s %s"), msg1, msg2);
 cleanup:
    VIR_FREE(msg1);
    VIR_FREE(msg2);
}

static PRL_RESULT
getJobResultHelper(PRL_HANDLE job, unsigned int timeout, PRL_HANDLE *result,
                   const char *filename, const char *funcname,
                   size_t linenr)
{
    PRL_RESULT ret, retCode;

    if (PRL_FAILED(ret = PrlJob_Wait(job, timeout))) {
        logPrlErrorHelper(ret, filename, funcname, linenr);
        goto cleanup;
    }

    if (PRL_FAILED(ret = PrlJob_GetRetCode(job, &retCode))) {
        logPrlErrorHelper(ret, filename, funcname, linenr);
        goto cleanup;
    }

    if (retCode) {
        PRL_HANDLE err_handle;

        ret = retCode;

        /* Sometimes it's possible to get additional error info. */
        if (PRL_FAILED(retCode = PrlJob_GetError(job, &err_handle))) {
            logPrlErrorHelper(ret, filename, funcname, linenr);
            goto cleanup;
        }

        if (PRL_FAILED(retCode = PrlEvent_GetErrCode(err_handle, &retCode))) {
            logPrlErrorHelper(ret, filename, funcname, linenr);
            if (PRL_ERR_NO_DATA != retCode)
                logPrlError(retCode);
            PrlHandle_Free(err_handle);
            goto cleanup;
        }

        logPrlEventErrorHelper(err_handle, filename, funcname, linenr);

        PrlHandle_Free(err_handle);
    } else {
        ret = PrlJob_GetResult(job, result);
        if (PRL_FAILED(ret)) {
            logPrlErrorHelper(ret, filename, funcname, linenr);
            PrlHandle_Free(*result);
            *result = NULL;
            goto cleanup;
        }

        ret = PRL_ERR_SUCCESS;
    }

 cleanup:
    PrlHandle_Free(job);
    return ret;
}

#define getJobResult(job, result)                       \
    getJobResultHelper(job, JOB_INFINIT_WAIT_TIMEOUT,   \
                       result, __FILE__, __FUNCTION__, __LINE__)

static PRL_RESULT
getDomainJobResultHelper(PRL_HANDLE job, virDomainObjPtr dom,
                         unsigned int timeout, PRL_HANDLE *result,
                         const char *filename, const char *funcname,
                         size_t linenr)
{
    PRL_RESULT pret;

    if (dom)
        virObjectUnlock(dom);
    pret = getJobResultHelper(job, timeout, result, filename, funcname, linenr);
    if (dom)
        virObjectLock(dom);

    return pret;
}

#define getDomainJobResult(job, dom, result)                            \
    getDomainJobResultHelper(job, dom, JOB_INFINIT_WAIT_TIMEOUT,        \
                             result, __FILE__, __FUNCTION__, __LINE__)

static PRL_RESULT
waitJobHelper(PRL_HANDLE job, unsigned int timeout,
              const char *filename, const char *funcname,
              size_t linenr)
{
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_RESULT ret;

    ret = getJobResultHelper(job, timeout, &result,
                             filename, funcname, linenr);
    PrlHandle_Free(result);
    return ret;
}

#define waitJob(job)                                        \
    waitJobHelper(job, JOB_INFINIT_WAIT_TIMEOUT, __FILE__,  \
                  __FUNCTION__, __LINE__)

static PRL_RESULT
waitDomainJobHelper(PRL_HANDLE job, virDomainObjPtr dom, unsigned int timeout,
                    const char *filename, const char *funcname,
                    size_t linenr)
{
    vzDomObjPtr pdom = dom->privateData;
    PRL_RESULT ret;

    if (pdom->job.cancelled) {
        virReportError(VIR_ERR_OPERATION_ABORTED, "%s",
                       _("Operation cancelled by client"));
        return PRL_ERR_FAILURE;
    }

    pdom->job.sdkJob = job;
    if (dom)
        virObjectUnlock(dom);
    ret = waitJobHelper(job, timeout, filename, funcname, linenr);
    if (dom)
        virObjectLock(dom);
    pdom->job.sdkJob = NULL;

    return ret;
}

#define waitDomainJob(job, dom)                                         \
    waitDomainJobHelper(job, dom, JOB_INFINIT_WAIT_TIMEOUT, __FILE__,   \
                        __FUNCTION__, __LINE__)

typedef PRL_RESULT (*prlsdkParamGetterType)(PRL_HANDLE, char*, PRL_UINT32*);

int
prlsdkCancelJob(virDomainObjPtr dom)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;
    PRL_HANDLE job;

    if (!privdom->job.active) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("no job is active on the domain"));
        return -1;
    }

   privdom->job.cancelled = true;
   job = PrlJob_Cancel(privdom->job.sdkJob);

   virObjectUnlock(dom);
   pret = waitJobHelper(job, JOB_INFINIT_WAIT_TIMEOUT,
                        __FILE__, __FUNCTION__, __LINE__);
   virObjectLock(dom);

   return PRL_FAILED(pret) ? -1 : 0;
}

static char*
prlsdkGetStringParamVar(prlsdkParamGetterType getter, PRL_HANDLE handle)
{
    PRL_RESULT pret;
    PRL_UINT32 buflen = 0;
    char *str = NULL;

    pret = getter(handle, NULL, &buflen);
    prlsdkCheckRetGoto(pret, error);

    if (VIR_ALLOC_N(str, buflen) < 0)
        goto error;

    pret = getter(handle, str, &buflen);
    prlsdkCheckRetGoto(pret, error);

    return str;

 error:
    VIR_FREE(str);
    return NULL;
}

static PRL_RESULT
prlsdkGetStringParamBuf(prlsdkParamGetterType getter,
                        PRL_HANDLE handle, char *buf, size_t size)
{
    PRL_UINT32 buflen = size;
    return getter(handle, buf, &buflen);
}

int
prlsdkInit(void)
{
    PRL_RESULT ret;

    /* Disable console output */
    PrlApi_SwitchConsoleLogging(0);

    ret = PrlApi_InitEx(PARALLELS_API_VER, PAM_SERVER, 0, 0);
    if (PRL_FAILED(ret)) {
        logPrlError(ret);
        return -1;
    }

    return 0;
};

void
prlsdkDeinit(void)
{
    PrlApi_Deinit();
};

int
prlsdkConnect(vzDriverPtr driver)
{
    int ret = -1;
    PRL_RESULT pret;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_HANDLE response = PRL_INVALID_HANDLE;
    char session_uuid[VIR_UUID_STRING_BRACED_BUFLEN];

    pret = PrlSrv_Create(&driver->server);
    prlsdkCheckRetExit(pret, -1);

    job = PrlSrv_LoginLocalEx(driver->server, NULL, 0,
                              PSL_HIGH_SECURITY, PACF_NON_INTERACTIVE_MODE);
    if (PRL_FAILED(getJobResult(job, &result)))
        goto cleanup;

    pret = PrlResult_GetParam(result, &response);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = prlsdkGetStringParamBuf(PrlLoginResponse_GetSessionUuid,
                                   response, session_uuid, sizeof(session_uuid));
    prlsdkCheckRetGoto(pret, cleanup);

    if (prlsdkUUIDParse(session_uuid, driver->session_uuid) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0) {
        PrlHandle_Free(driver->server);
        driver->server = PRL_INVALID_HANDLE;
    }

    PrlHandle_Free(result);
    PrlHandle_Free(response);

    return ret;
}

void
prlsdkDisconnect(vzDriverPtr driver)
{
    PRL_HANDLE job;

    job = PrlSrv_Logoff(driver->server);
    waitJob(job);

    PrlHandle_Free(driver->server);
}

static int
prlsdkSdkDomainLookup(vzDriverPtr driver,
                      const char *id,
                      unsigned int flags,
                      PRL_HANDLE *sdkdom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_RESULT pret = PRL_ERR_UNINITIALIZED;
    int ret = -1;

    job = PrlSrv_GetVmConfig(driver->server, id, flags);
    if (PRL_FAILED(getJobResult(job, &result)))
        goto cleanup;

    pret = PrlResult_GetParamByIndex(result, 0, sdkdom);
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;

 cleanup:
    PrlHandle_Free(result);
    return ret;
}

static void
prlsdkUUIDFormat(const unsigned char *uuid, char *uuidstr)
{
    virUUIDFormat(uuid, uuidstr + 1);

    uuidstr[0] = '{';
    uuidstr[VIR_UUID_STRING_BUFLEN] = '}';
    uuidstr[VIR_UUID_STRING_BUFLEN + 1] = '\0';
}

static PRL_HANDLE
prlsdkSdkDomainLookupByUUID(vzDriverPtr driver, const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BRACED_BUFLEN];
    PRL_HANDLE sdkdom = PRL_INVALID_HANDLE;

    prlsdkUUIDFormat(uuid, uuidstr);

    if (prlsdkSdkDomainLookup(driver, uuidstr,
                              PGVC_SEARCH_BY_UUID, &sdkdom) < 0) {
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        return PRL_INVALID_HANDLE;
    }

    return sdkdom;
}

PRL_HANDLE
prlsdkSdkDomainLookupByName(vzDriverPtr driver, const char *name)
{
    PRL_HANDLE sdkdom = PRL_INVALID_HANDLE;

    if (prlsdkSdkDomainLookup(driver, name,
                              PGVC_SEARCH_BY_NAME, &sdkdom) < 0) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        return PRL_INVALID_HANDLE;
    }

    return sdkdom;
}

static int
prlsdkUUIDParse(const char *uuidstr, unsigned char *uuid)
{
    char *tmp = NULL;
    int ret = -1;

    virCheckNonNullArgGoto(uuidstr, error);
    virCheckNonNullArgGoto(uuid, error);

    if (VIR_STRDUP(tmp, uuidstr) < 0)
        goto error;

    tmp[strlen(tmp) - 1] = '\0';

    /* trim curly braces */
    if (virUUIDParse(tmp + 1, uuid) < 0)
        goto error;

    ret = 0;
 error:
    VIR_FREE(tmp);
    return ret;
}

static int
prlsdkGetDomainState(virDomainObjPtr dom, PRL_HANDLE sdkdom, VIRTUAL_MACHINE_STATE_PTR vmState)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_HANDLE vmInfo = PRL_INVALID_HANDLE;
    PRL_RESULT pret;
    int ret = -1;

    job = PrlVm_GetState(sdkdom);

    if (PRL_FAILED(getDomainJobResult(job, dom, &result)))
        goto cleanup;

    pret = PrlResult_GetParamByIndex(result, 0, &vmInfo);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmInfo_GetState(vmInfo, vmState);
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;

 cleanup:
    PrlHandle_Free(vmInfo);
    PrlHandle_Free(result);
    return ret;
}

static int
prlsdkAddDomainVideoInfoCt(virDomainDefPtr def)
{
    virDomainVideoDefPtr video = NULL;
    int ret = -1;

    if (def->ngraphics == 0)
        return 0;

    if (VIR_ALLOC(video) < 0)
        goto cleanup;

    video->type = VIR_DOMAIN_VIDEO_TYPE_PARALLELS;
    video->vram = 0;
    video->heads = 1;

    if (VIR_APPEND_ELEMENT(def->videos, def->nvideos, video) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virDomainVideoDefFree(video);

    return ret;
}

static int
prlsdkAddDomainVideoInfoVm(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    virDomainVideoDefPtr video = NULL;
    virDomainVideoAccelDefPtr accel = NULL;
    PRL_RESULT ret;
    PRL_UINT32 videoRam;

    /* video info */
    ret = PrlVmCfg_GetVideoRamSize(sdkdom, &videoRam);
    prlsdkCheckRetGoto(ret, error);

    if (VIR_ALLOC(video) < 0)
        goto error;

    if (VIR_ALLOC(accel) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(def->videos, def->nvideos, video) < 0)
        goto error;

    video->type = VIR_DOMAIN_VIDEO_TYPE_VGA;
    video->vram = videoRam << 10; /* from mbibytes to kbibytes */
    video->heads = 1;
    video->accel = accel;

    return 0;

 error:
    VIR_FREE(accel);
    virDomainVideoDefFree(video);
    return -1;
}

static int
prlsdkGetDiskId(PRL_HANDLE disk, int *bus, char **dst)
{
    PRL_RESULT pret;
    PRL_UINT32 pos, ifType;

    pret = PrlVmDev_GetStackIndex(disk, &pos);
    prlsdkCheckRetExit(pret, -1);

    pret = PrlVmDev_GetIfaceType(disk, &ifType);
    prlsdkCheckRetExit(pret, -1);

    switch (ifType) {
    case PMS_IDE_DEVICE:
        *bus = VIR_DOMAIN_DISK_BUS_IDE;
        *dst = virIndexToDiskName(pos, "hd");
        break;
    case PMS_SCSI_DEVICE:
    case PMS_UNKNOWN_DEVICE:
        *bus = VIR_DOMAIN_DISK_BUS_SCSI;
        *dst = virIndexToDiskName(pos, "sd");
        break;
    case PMS_SATA_DEVICE:
        *bus = VIR_DOMAIN_DISK_BUS_SATA;
        *dst = virIndexToDiskName(pos, "sd");
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown disk bus: %X"), ifType);
        return -1;
    }

    if (NULL == *dst)
        return -1;

    return 0;
}

static int
prlsdkGetDiskInfo(vzDriverPtr driver,
                  PRL_HANDLE prldisk,
                  virDomainDiskDefPtr disk,
                  bool isCdrom,
                  bool isCt)
{
    char *buf = NULL;
    PRL_RESULT pret;
    PRL_UINT32 emulatedType;
    PRL_UINT32 size;
    virDomainDeviceDriveAddressPtr address;
    int busIdx, devIdx;
    int ret = -1;

    pret = PrlVmDev_GetEmulatedType(prldisk, &emulatedType);
    prlsdkCheckRetGoto(pret, cleanup);
    if (emulatedType == PDT_USE_IMAGE_FILE) {
        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
        if (isCdrom) {
            virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
        } else {
            if (isCt)
                virDomainDiskSetFormat(disk, driver->vzCaps.ctDiskFormat);
            else
                virDomainDiskSetFormat(disk, driver->vzCaps.vmDiskFormat);
        }
    } else {
        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
        virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
    }

    if (isCdrom) {
        disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
        disk->src->readonly = true;
    } else {
        disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    }

    if (!(buf = prlsdkGetStringParamVar(PrlVmDev_GetFriendlyName, prldisk)))
        goto cleanup;

    if (*buf != '\0' && virDomainDiskSetSource(disk, buf) < 0)
        goto cleanup;

    if (prlsdkGetDiskId(prldisk, &disk->bus, &disk->dst) < 0)
        goto cleanup;

    if (virDiskNameToBusDeviceIndex(disk, &busIdx, &devIdx) < 0)
        goto cleanup;

    address = &disk->info.addr.drive;
    address->bus = busIdx;
    address->target = 0;
    address->unit = devIdx;

    disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

    if (!isCdrom) {
        if (!(disk->serial = prlsdkGetStringParamVar(PrlVmDevHd_GetSerialNumber, prldisk)))
            goto cleanup;

        if (*disk->serial == '\0')
            VIR_FREE(disk->serial);
    }

    if (virDomainDiskSetDriver(disk, "vz") < 0)
        goto cleanup;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        pret = PrlVmDevHd_GetDiskSize(prldisk, &size);
        prlsdkCheckRetGoto(pret, cleanup);
        /* from MiB to bytes */
        disk->src->capacity = ((unsigned long long)size) << 20;
    }

    ret = 0;

 cleanup:
    VIR_FREE(buf);
    return ret;
}

static int
prlsdkGetFSInfo(PRL_HANDLE prldisk,
                virDomainFSDefPtr fs)
{
    char *buf = NULL;
    int ret = -1;
    char **matches = NULL;
    virURIPtr uri = NULL;

    fs->type = VIR_DOMAIN_FS_TYPE_FILE;
    fs->fsdriver = VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP;
    fs->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;
    fs->wrpolicy = VIR_DOMAIN_FS_WRPOLICY_DEFAULT;
    fs->format = VIR_STORAGE_FILE_PLOOP;

    fs->readonly = false;
    fs->symlinksResolved = false;

    if (!(buf = prlsdkGetStringParamVar(PrlVmDevHd_GetStorageURL, prldisk)))
        goto cleanup;

    if (!virStringIsEmpty(buf)) {
        if (!(uri = virURIParse(buf)))
            goto cleanup;
        if (STRNEQ("libvirt", uri->scheme)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown uri scheme: '%s'"),
                           uri->scheme);
            goto cleanup;
        }

        if (!(matches = virStringSplitCount(uri->path, "/", 0, NULL)) ||
            !matches[0]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("splitting StorageUrl failed %s"), uri->path);
            goto cleanup;
        }
        if (!matches[1]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("can't identify pool in uri %s "), uri->path);
            goto cleanup;
        }
        if (!matches[2]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("can't identify volume in uri %s"), uri->path);
            goto cleanup;
        }
        fs->type = VIR_DOMAIN_FS_TYPE_VOLUME;
        if (VIR_ALLOC(fs->src->srcpool) < 0)
            goto cleanup;
        if (VIR_STRDUP(fs->src->srcpool->pool, matches[1]) < 0)
            goto cleanup;
        if (VIR_STRDUP(fs->src->srcpool->volume, matches[2]) < 0)
            goto cleanup;
        VIR_FREE(buf);
    } else {
        fs->type = VIR_DOMAIN_FS_TYPE_FILE;
        if (!(buf = prlsdkGetStringParamVar(PrlVmDev_GetImagePath, prldisk)))
            goto cleanup;

        fs->src->path = buf;
        buf = NULL;
    }
    if (!(buf = prlsdkGetStringParamVar(PrlVmDevHd_GetMountPoint, prldisk)))
        goto cleanup;

    fs->dst = buf;
    buf = NULL;

    ret = 0;

 cleanup:
    VIR_FREE(buf);
    virStringListFree(matches);
    return ret;
}

static int
prlsdkAddDomainHardDisksInfo(vzDriverPtr driver, PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    PRL_RESULT pret;
    PRL_UINT32 hddCount;
    PRL_UINT32 i;
    PRL_HANDLE hdd = PRL_INVALID_HANDLE;
    virDomainDiskDefPtr disk = NULL;
    virDomainFSDefPtr fs = NULL;

    pret = PrlVmCfg_GetHardDisksCount(sdkdom, &hddCount);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < hddCount; ++i) {

        PRL_UINT32 emulatedType;

        pret = PrlVmCfg_GetHardDisk(sdkdom, i, &hdd);
        prlsdkCheckRetGoto(pret, error);

        pret = PrlVmDev_GetEmulatedType(hdd, &emulatedType);
        prlsdkCheckRetGoto(pret, error);

        if (IS_CT(def) &&
            prlsdkInBootList(sdkdom, hdd)) {

            if (!(fs = virDomainFSDefNew()))
                goto error;

            if (prlsdkGetFSInfo(hdd, fs) < 0)
                goto error;

            if (virDomainFSInsert(def, fs) < 0)
                goto error;

            fs = NULL;
            PrlHandle_Free(hdd);
            hdd = PRL_INVALID_HANDLE;
        } else {
            if (!(disk = virDomainDiskDefNew(NULL)))
                goto error;

            if (prlsdkGetDiskInfo(driver, hdd, disk, false, IS_CT(def)) < 0)
                goto error;

            if (virDomainDiskInsert(def, disk) < 0)
                goto error;

            disk = NULL;
            PrlHandle_Free(hdd);
            hdd = PRL_INVALID_HANDLE;
        }
    }

    return 0;

 error:
    PrlHandle_Free(hdd);
    virDomainDiskDefFree(disk);
    virDomainFSDefFree(fs);
    return -1;
}

static int
prlsdkAddDomainOpticalDisksInfo(vzDriverPtr driver, PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    PRL_RESULT pret;
    PRL_UINT32 cdromsCount;
    PRL_UINT32 i;
    PRL_HANDLE cdrom = PRL_INVALID_HANDLE;
    virDomainDiskDefPtr disk = NULL;

    pret = PrlVmCfg_GetOpticalDisksCount(sdkdom, &cdromsCount);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < cdromsCount; ++i) {
        pret = PrlVmCfg_GetOpticalDisk(sdkdom, i, &cdrom);
        prlsdkCheckRetGoto(pret, error);

        if (!(disk = virDomainDiskDefNew(NULL)))
            goto error;

        if (prlsdkGetDiskInfo(driver, cdrom, disk, true, IS_CT(def)) < 0)
            goto error;

        PrlHandle_Free(cdrom);
        cdrom = PRL_INVALID_HANDLE;

        if (virDomainDiskInsert(def, disk) < 0)
            goto error;
    }

    return 0;

 error:
    PrlHandle_Free(cdrom);
    virDomainDiskDefFree(disk);
    return -1;
}

static virNetDevIPAddrPtr
prlsdkParseNetAddress(char *addr)
{
    char *maskstr = NULL;
    int nbits;
    virSocketAddr mask;
    virNetDevIPAddrPtr ip = NULL, ret = NULL;

    if (!(maskstr = strchr(addr, '/')))
        goto cleanup;

    *maskstr = '\0';
    ++maskstr;

    if (VIR_ALLOC(ip) < 0)
        goto cleanup;

    if (virSocketAddrParse(&ip->address, addr, AF_UNSPEC) < 0)
        goto cleanup;

    if (virSocketAddrParse(&mask, maskstr, AF_UNSPEC) < 0)
        goto cleanup;

    if ((nbits = virSocketAddrGetNumNetmaskBits(&mask)) < 0)
        goto cleanup;
    ip->prefix = nbits;

    ret = ip;
    ip = NULL;

 cleanup:
    if (!ret)
        VIR_WARN("cannot parse network address '%s'", addr);

    VIR_FREE(ip);
    VIR_FREE(addr);

    return ret;
}

static int
prlsdkGetNetAddresses(PRL_HANDLE sdknet, virDomainNetDefPtr net)
{
    int ret = -1;
    PRL_HANDLE addrlist = PRL_INVALID_HANDLE;
    PRL_UINT32 num;
    size_t i;
    PRL_RESULT pret;

    pret = PrlVmDevNet_GetNetAddresses(sdknet, &addrlist);
    prlsdkCheckRetGoto(pret, cleanup);

    PrlStrList_GetItemsCount(addrlist, &num);
    prlsdkCheckRetGoto(pret, cleanup);

    for (i = 0; i < num; ++i) {
        virNetDevIPAddrPtr ip = NULL;
        PRL_UINT32 buflen = 0;
        char *addr;

        pret = PrlStrList_GetItem(addrlist, i, NULL, &buflen);
        prlsdkCheckRetGoto(pret, cleanup);

        if (VIR_ALLOC_N(addr, buflen) < 0)
            goto cleanup;

        pret = PrlStrList_GetItem(addrlist, i, addr, &buflen);
        prlsdkCheckRetGoto(pret, cleanup);

        if (!(ip = prlsdkParseNetAddress(addr)))
            continue;

        if (VIR_APPEND_ELEMENT(net->guestIP.ips, net->guestIP.nips, ip) < 0) {
            VIR_FREE(ip);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:

    PrlHandle_Free(addrlist);
    return ret;
}

static int
prlsdkGetRoutes(PRL_HANDLE sdknet, virDomainNetDefPtr net)
{
    int ret = -1;
    char *gw = NULL;
    char *gw6 = NULL;
    virNetDevIPRoutePtr route = NULL;

    if (!(gw = prlsdkGetStringParamVar(PrlVmDevNet_GetDefaultGateway, sdknet)))
        goto cleanup;

    if (!(gw6 = prlsdkGetStringParamVar(PrlVmDevNet_GetDefaultGatewayIPv6, sdknet)))
        goto cleanup;

    if (*gw != '\0') {

        if (!(route = virNetDevIPRouteCreate(_("Domain interface"),
                                               "ipv4", VIR_SOCKET_ADDR_IPV4_ALL,
                                               NULL, gw, 0, true, 0, false)))
            goto cleanup;

        if (VIR_APPEND_ELEMENT(net->guestIP.routes, net->guestIP.nroutes, route) < 0)
            goto cleanup;
    }

    if (*gw6 != '\0') {
        if (!(route = virNetDevIPRouteCreate(_("Domain interface"),
                                               "ipv6", VIR_SOCKET_ADDR_IPV6_ALL,
                                               NULL, gw6, 0, true, 0, false)))
            goto cleanup;

        if (VIR_APPEND_ELEMENT(net->guestIP.routes, net->guestIP.nroutes, route) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virNetDevIPRouteFree(route);
    VIR_FREE(gw);
    VIR_FREE(gw6);

    return ret;
}

static int
prlsdkGetNetInfo(PRL_HANDLE netAdapter, virDomainNetDefPtr net, bool isCt)
{
    char macstr[VIR_MAC_STRING_BUFLEN];
    PRL_UINT32 netAdapterIndex;
    PRL_UINT32 emulatedType;
    PRL_RESULT pret;
    PRL_BOOL isConnected, isMacFilter;
    int ret = -1;

    /* use device name, shown by prlctl as target device
     * for identifying network adapter in virDomainDefineXML */
    if (!(net->ifname = prlsdkGetStringParamVar(PrlVmDevNet_GetHostInterfaceName,
                                                netAdapter)))
        goto cleanup;

    pret = PrlVmDev_GetIndex(netAdapter, &netAdapterIndex);
    prlsdkCheckRetGoto(pret, cleanup);

    if (isCt && netAdapterIndex == (PRL_UINT32) -1) {
        /* venet devices don't have mac address and
         * always up */
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
        net->type = VIR_DOMAIN_NET_TYPE_NETWORK;
        if (VIR_STRDUP(net->data.network.name,
                       PARALLELS_DOMAIN_ROUTED_NETWORK_NAME) < 0)
            goto cleanup;
        return 0;
    }

    pret = prlsdkGetStringParamBuf(PrlVmDevNet_GetMacAddressCanonical,
                                   netAdapter, macstr, sizeof(macstr));
    prlsdkCheckRetGoto(pret, cleanup);

    if (virMacAddrParse(macstr, &net->mac) < 0)
        goto cleanup;

    if (prlsdkGetNetAddresses(netAdapter, net) < 0)
        goto cleanup;

    if (prlsdkGetRoutes(netAdapter, net) < 0)
        goto cleanup;

    pret = PrlVmDev_GetEmulatedType(netAdapter, &emulatedType);
    prlsdkCheckRetGoto(pret, cleanup);

    if (emulatedType == PNA_ROUTED) {
        net->type = VIR_DOMAIN_NET_TYPE_NETWORK;
        if (VIR_STRDUP(net->data.network.name,
                       PARALLELS_DOMAIN_ROUTED_NETWORK_NAME) < 0)
            goto cleanup;
    } else {
        char *netid =
              prlsdkGetStringParamVar(PrlVmDevNet_GetVirtualNetworkId,
                                      netAdapter);

        if (emulatedType == PNA_BRIDGE) {
            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            if (netid)
                net->data.bridge.brname = netid;
        } else {
            net->type = VIR_DOMAIN_NET_TYPE_NETWORK;
            if (netid)
                net->data.network.name = netid;
        }
    }

    if (!isCt) {
        PRL_VM_NET_ADAPTER_TYPE type;
        pret = PrlVmDevNet_GetAdapterType(netAdapter, &type);
        prlsdkCheckRetGoto(pret, cleanup);

        switch (type) {
        case PNT_RTL:
            if (VIR_STRDUP(net->model, "rtl8139") < 0)
                goto cleanup;
            break;
        case PNT_E1000:
            if (VIR_STRDUP(net->model, "e1000") < 0)
                goto cleanup;
            break;
        case PNT_VIRTIO:
            if (VIR_STRDUP(net->model, "virtio") < 0)
                goto cleanup;
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown adapter type: %X"), type);
            goto cleanup;
        }
    }

    pret = PrlVmDev_IsConnected(netAdapter, &isConnected);
    prlsdkCheckRetGoto(pret, cleanup);

    if (isConnected)
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
    else
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;

    pret = PrlVmDevNet_IsPktFilterPreventMacSpoof(netAdapter, &isMacFilter);
    prlsdkCheckRetGoto(pret, cleanup);

    net->trustGuestRxFilters = isMacFilter ? VIR_TRISTATE_BOOL_YES :
                                             VIR_TRISTATE_BOOL_NO;

    ret = 0;
 cleanup:
    return ret;
}

static int
prlsdkAddDomainNetInfo(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    virDomainNetDefPtr net = NULL;
    PRL_RESULT ret;
    PRL_HANDLE netAdapter;
    PRL_UINT32 netAdaptersCount;
    PRL_UINT32 i;

    ret = PrlVmCfg_GetNetAdaptersCount(sdkdom, &netAdaptersCount);
    prlsdkCheckRetGoto(ret, error);
    for (i = 0; i < netAdaptersCount; ++i) {
        ret = PrlVmCfg_GetNetAdapter(sdkdom, i, &netAdapter);
        prlsdkCheckRetGoto(ret, error);

        if (VIR_ALLOC(net) < 0)
            goto error;

        if (prlsdkGetNetInfo(netAdapter, net, IS_CT(def)) < 0)
            goto error;

        PrlHandle_Free(netAdapter);
        netAdapter = PRL_INVALID_HANDLE;

        if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0)
            goto error;
    }

    return 0;

 error:
    PrlHandle_Free(netAdapter);
    virDomainNetDefFree(net);
    return -1;
}

static int
prlsdkGetSerialInfo(PRL_HANDLE serialPort, virDomainChrDefPtr chr)
{
    PRL_RESULT pret;
    PRL_UINT32 serialPortIndex;
    PRL_UINT32 emulatedType;
    char *friendlyName = NULL;
    PRL_SERIAL_PORT_SOCKET_OPERATION_MODE socket_mode;
    char *uristr = NULL;
    virURIPtr uri = NULL;
    int ret = -1;

    chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
    chr->targetTypeAttr = false;
    pret = PrlVmDev_GetIndex(serialPort, &serialPortIndex);
    prlsdkCheckRetGoto(pret, cleanup);
    chr->target.port = serialPortIndex;

    pret = PrlVmDev_GetEmulatedType(serialPort, &emulatedType);
    prlsdkCheckRetGoto(pret, cleanup);

    if (!(friendlyName = prlsdkGetStringParamVar(PrlVmDev_GetFriendlyName,
                                                 serialPort)))
        goto cleanup;

    pret = PrlVmDevSerial_GetSocketMode(serialPort, &socket_mode);
    prlsdkCheckRetGoto(pret, cleanup);

    switch (emulatedType) {
    case PDT_USE_OUTPUT_FILE:
        chr->source->type = VIR_DOMAIN_CHR_TYPE_FILE;
        chr->source->data.file.path = friendlyName;
        friendlyName = NULL;
        break;
    case PDT_USE_SERIAL_PORT_SOCKET_MODE:
        chr->source->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        chr->source->data.nix.path = friendlyName;
        chr->source->data.nix.listen = socket_mode == PSP_SERIAL_SOCKET_SERVER;
        friendlyName = NULL;
        break;
    case PDT_USE_REAL_DEVICE:
        chr->source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        chr->source->data.file.path = friendlyName;
        friendlyName = NULL;
        break;
    case PDT_USE_TCP:
        chr->source->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (virAsprintf(&uristr, "tcp://%s", friendlyName) < 0)
            goto cleanup;
        if (!(uri = virURIParse(uristr)))
            goto cleanup;
        if (VIR_STRDUP(chr->source->data.tcp.host, uri->server) < 0)
            goto cleanup;
        if (virAsprintf(&chr->source->data.tcp.service, "%d", uri->port) < 0)
            goto cleanup;
        chr->source->data.tcp.listen = socket_mode == PSP_SERIAL_SOCKET_SERVER;
        break;
    case PDT_USE_UDP:
        chr->source->type = VIR_DOMAIN_CHR_TYPE_UDP;
        if (virAsprintf(&uristr, "udp://%s", friendlyName) < 0)
            goto cleanup;
        if (!(uri = virURIParse(uristr)))
            goto cleanup;
        if (VIR_STRDUP(chr->source->data.udp.bindHost, uri->server) < 0)
            goto cleanup;
        if (virAsprintf(&chr->source->data.udp.bindService, "%d", uri->port) < 0)
            goto cleanup;
        if (VIR_STRDUP(chr->source->data.udp.connectHost, uri->server) < 0)
            goto cleanup;
        if (virAsprintf(&chr->source->data.udp.connectService, "%d", uri->port) < 0)
            goto cleanup;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown serial type: %X"), emulatedType);
        goto cleanup;
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(friendlyName);
    VIR_FREE(uristr);
    virURIFree(uri);

    return ret;
}


static int
prlsdkAddSerialInfo(PRL_HANDLE sdkdom,
                    virDomainChrDefPtr **serials,
                    size_t *nserials)
{
    PRL_RESULT ret;
    PRL_HANDLE serialPort;
    PRL_UINT32 serialPortsCount;
    PRL_UINT32 i;
    virDomainChrDefPtr chr = NULL;

    ret = PrlVmCfg_GetSerialPortsCount(sdkdom, &serialPortsCount);
    prlsdkCheckRetGoto(ret, cleanup);
    for (i = 0; i < serialPortsCount; ++i) {
        ret = PrlVmCfg_GetSerialPort(sdkdom, i, &serialPort);
        prlsdkCheckRetGoto(ret, cleanup);

        if (!(chr = virDomainChrDefNew(NULL)))
            goto cleanup;

        if (prlsdkGetSerialInfo(serialPort, chr))
            goto cleanup;

        PrlHandle_Free(serialPort);
        serialPort = PRL_INVALID_HANDLE;

        if (VIR_APPEND_ELEMENT(*serials, *nserials, chr) < 0)
            goto cleanup;
    }

    return 0;

 cleanup:
    PrlHandle_Free(serialPort);
    virDomainChrDefFree(chr);
    return -1;
}


static int
prlsdkAddDomainHardware(vzDriverPtr driver, PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    if (IS_CT(def)) {
        if (prlsdkAddDomainVideoInfoCt(def) < 0)
            goto error;
    } else {
        if (prlsdkAddDomainVideoInfoVm(sdkdom, def) < 0)
            goto error;
    }

    if (prlsdkAddDomainHardDisksInfo(driver, sdkdom, def) < 0)
        goto error;

    if (prlsdkAddDomainOpticalDisksInfo(driver, sdkdom, def) < 0)
        goto error;

    if (prlsdkAddDomainNetInfo(sdkdom, def) < 0)
        goto error;

    if (prlsdkAddSerialInfo(sdkdom,
                            &def->serials,
                            &def->nserials) < 0)
        goto error;

    return 0;
 error:
    return -1;
}


static int
prlsdkAddVNCInfo(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    virDomainGraphicsDefPtr gr = NULL;
    PRL_VM_REMOTE_DISPLAY_MODE vncMode;
    PRL_UINT32 port;
    PRL_RESULT pret;
    char *passwd = NULL;

    pret = PrlVmCfg_GetVNCMode(sdkdom, &vncMode);
    prlsdkCheckRetGoto(pret, error);

    if (vncMode == PRD_DISABLED)
        return 0;

    if (VIR_ALLOC(gr) < 0)
        goto error;

    if (!(passwd = prlsdkGetStringParamVar(PrlVmCfg_GetVNCPassword, sdkdom)))
        goto error;

    if (*passwd != '\0') {
        gr->data.vnc.auth.passwd = passwd;
        passwd = NULL;
    }

    pret = PrlVmCfg_GetVNCPort(sdkdom, &port);
    prlsdkCheckRetGoto(pret, error);

    gr->data.vnc.autoport = (vncMode == PRD_AUTO);
    gr->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
    gr->data.vnc.port = port;

    if (VIR_ALLOC(gr->listens) < 0)
        goto error;

    gr->nListens = 1;

    if (!(gr->listens[0].address = prlsdkGetStringParamVar(PrlVmCfg_GetVNCHostName,
                                                           sdkdom)))
        goto error;

    gr->listens[0].type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;

    if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, gr) < 0)
        goto error;

    return 0;

 error:
    virDomainGraphicsDefFree(gr);
    VIR_FREE(passwd);
    return -1;
}

static void
prlsdkConvertDomainState(VIRTUAL_MACHINE_STATE domainState,
                         PRL_UINT32 envId,
                         virDomainObjPtr dom)
{
    switch (domainState) {
    case VMS_STOPPED:
    case VMS_MOUNTED:
        virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        dom->def->id = -1;
        break;
    case VMS_STARTING:
    case VMS_COMPACTING:
    case VMS_RESETTING:
    case VMS_PAUSING:
    case VMS_RECONNECTING:
    case VMS_RUNNING:
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_BOOTED);
        dom->def->id = envId;
        break;
    case VMS_PAUSED:
        virDomainObjSetState(dom, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_USER);
        dom->def->id = envId;
        break;
    case VMS_SUSPENDED:
    case VMS_DELETING_STATE:
    case VMS_SUSPENDING_SYNC:
        virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SAVED);
        dom->def->id = -1;
        break;
    case VMS_STOPPING:
        virDomainObjSetState(dom, VIR_DOMAIN_SHUTDOWN,
                             VIR_DOMAIN_SHUTDOWN_USER);
        dom->def->id = envId;
        break;
    case VMS_SNAPSHOTING:
        virDomainObjSetState(dom, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_SNAPSHOT);
        dom->def->id = envId;
        break;
    case VMS_MIGRATING:
        virDomainObjSetState(dom, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_MIGRATION);
        dom->def->id = envId;
        break;
    case VMS_SUSPENDING:
        virDomainObjSetState(dom, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_SAVE);
        dom->def->id = envId;
        break;
    case VMS_RESTORING:
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_RESTORED);
        dom->def->id = envId;
        break;
    case VMS_CONTINUING:
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);
        dom->def->id = envId;
        break;
    case VMS_RESUMING:
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_RESTORED);
        dom->def->id = envId;
        break;
    case VMS_UNKNOWN:
    default:
        virDomainObjSetState(dom, VIR_DOMAIN_NOSTATE,
                             VIR_DOMAIN_NOSTATE_UNKNOWN);
        dom->def->id = -1;
        break;
    }
}

static int
prlsdkConvertCpuInfo(PRL_HANDLE sdkdom,
                     virDomainDefPtr def,
                     virDomainXMLOptionPtr xmlopt)
{
    char *buf;
    int hostcpus;
    PRL_UINT32 cpuCount;
    PRL_RESULT pret;
    int ret = -1;

    if ((hostcpus = virHostCPUGetCount()) < 0)
        goto cleanup;

    /* get number of CPUs */
    pret = PrlVmCfg_GetCpuCount(sdkdom, &cpuCount);
    prlsdkCheckRetGoto(pret, cleanup);

    if (cpuCount > hostcpus)
        cpuCount = hostcpus;

    if (virDomainDefSetVcpusMax(def, cpuCount, xmlopt) < 0)
        goto cleanup;

    if (virDomainDefSetVcpus(def, cpuCount) < 0)
        goto cleanup;

    if (!(buf = prlsdkGetStringParamVar(PrlVmCfg_GetCpuMask, sdkdom)))
        goto cleanup;

    if (strlen(buf) == 0) {
        if (!(def->cpumask = virBitmapNew(hostcpus)))
            goto cleanup;
        virBitmapSetAll(def->cpumask);
    } else {
        if (virBitmapParse(buf, &def->cpumask, hostcpus) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    return ret;
}

static int
prlsdkConvertDomainType(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    PRL_VM_TYPE domainType;
    PRL_RESULT pret;

    pret = PrlVmCfg_GetVmType(sdkdom, &domainType);
    prlsdkCheckRetGoto(pret, error);

    switch (domainType) {
    case PVT_VM:
        def->os.type = VIR_DOMAIN_OSTYPE_HVM;
        break;
    case PVT_CT:
        def->os.type = VIR_DOMAIN_OSTYPE_EXE;
        if (VIR_STRDUP(def->os.init, "/sbin/init") < 0)
            return -1;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown domain type: %X"), domainType);
        return -1;
    }

    return 0;

 error:
    return -1;
}

static int
prlsdkConvertCpuMode(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    PRL_RESULT pret;
    PRL_CPU_MODE cpuMode;

    pret = PrlVmCfg_GetCpuMode(sdkdom, &cpuMode);
    prlsdkCheckRetGoto(pret, error);

    switch (cpuMode) {
    case PCM_CPU_MODE_32:
        def->os.arch = VIR_ARCH_I686;
        break;
    case PCM_CPU_MODE_64:
        def->os.arch = VIR_ARCH_X86_64;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU mode: %X"), cpuMode);
        return -1;
    }

    return 0;
 error:
    return -1;
}

static PRL_HANDLE
prlsdkGetDevByDevIndex(PRL_HANDLE sdkdom, PRL_DEVICE_TYPE type, PRL_UINT32 devIndex)
{
    PRL_RESULT pret;
    PRL_UINT32 index, num;
    PRL_HANDLE dev = PRL_INVALID_HANDLE;
    size_t i;

    pret = PrlVmCfg_GetDevsCountByType(sdkdom, type, &num);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < num; ++i) {
        pret = PrlVmCfg_GetDevByType(sdkdom, type, i, &dev);
        prlsdkCheckRetGoto(pret, error);

        pret = PrlVmDev_GetIndex(dev, &index);
        prlsdkCheckRetGoto(pret, error);

        if (index == devIndex)
            break;

        PrlHandle_Free(dev);
        dev = PRL_INVALID_HANDLE;
    }

    return dev;

 error:
    PrlHandle_Free(dev);
    return PRL_INVALID_HANDLE;
}

static virDomainDiskDefPtr
virFindDiskBootIndex(virDomainDefPtr def, virDomainDiskDevice type, int index)
{
    size_t i;
    int c = 0;

    for (i = 0; i < def->ndisks; ++i) {
        if (def->disks[i]->device != type)
            continue;
        if (c == index)
            return def->disks[i];
        ++c;
    }

    return NULL;
}

static bool
prlsdkInBootList(PRL_HANDLE sdkdom,
                 PRL_HANDLE sdktargetdev)
{
    bool ret = false;
    PRL_RESULT pret;
    PRL_UINT32 bootNum;
    PRL_HANDLE bootDev = PRL_INVALID_HANDLE;
    PRL_BOOL inUse;
    PRL_DEVICE_TYPE sdkType, targetType;
    PRL_UINT32 sdkIndex, targetIndex;
    size_t i;

    pret = PrlVmDev_GetType(sdktargetdev, &targetType);
    prlsdkCheckRetExit(pret, -1);

    pret = PrlVmDev_GetIndex(sdktargetdev, &targetIndex);
    prlsdkCheckRetExit(pret, -1);

    pret = PrlVmCfg_GetBootDevCount(sdkdom, &bootNum);
    prlsdkCheckRetExit(pret, -1);

    for (i = 0; i < bootNum; ++i) {
        pret = PrlVmCfg_GetBootDev(sdkdom, i, &bootDev);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlBootDev_IsInUse(bootDev, &inUse);
        prlsdkCheckRetGoto(pret, cleanup);

        if (!inUse) {
            PrlHandle_Free(bootDev);
            bootDev = PRL_INVALID_HANDLE;
            continue;
        }

        pret = PrlBootDev_GetType(bootDev, &sdkType);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlBootDev_GetIndex(bootDev, &sdkIndex);
        prlsdkCheckRetGoto(pret, cleanup);

        PrlHandle_Free(bootDev);
        bootDev = PRL_INVALID_HANDLE;

        if (sdkIndex == targetIndex && sdkType == targetType) {
            ret = true;
            break;
        }
    }

 cleanup:
    PrlHandle_Free(bootDev);
    return ret;
}
static int
prlsdkBootOrderCheck(PRL_HANDLE sdkdom, PRL_DEVICE_TYPE sdkType, int sdkIndex,
                     virDomainDefPtr def, int bootIndex)
{
    char *sdkName = NULL;
    PRL_HANDLE dev = PRL_INVALID_HANDLE;
    virDomainDiskDefPtr disk;
    virDomainDiskDevice device;
    int bus;
    char *dst = NULL;
    int ret = -1;

    dev = prlsdkGetDevByDevIndex(sdkdom, sdkType, sdkIndex);
    if (dev == PRL_INVALID_HANDLE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Can't find boot device of type: %d, device index: %d"),
                       sdkType, sdkIndex);
        return -1;
    }

    switch (sdkType) {
    case PDE_OPTICAL_DISK:
    case PDE_HARD_DISK:
        switch (sdkType) {
        case PDE_OPTICAL_DISK:
            device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            break;
        case PDE_HARD_DISK:
            device = VIR_DOMAIN_DISK_DEVICE_DISK;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported disk type %d"), sdkType);
            goto cleanup;
        }

        if (!(disk = virFindDiskBootIndex(def, device, bootIndex))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Can't find boot device of type: %s, index: %d"),
                           virDomainDiskDeviceTypeToString(device), bootIndex);
            goto cleanup;
        }

        if (prlsdkGetDiskId(dev, &bus, &dst) < 0)
            goto cleanup;

        if (!(bus == disk->bus && STREQ(disk->dst, dst)))
            VIR_WARN("Unrepresentable boot order configuration");

        break;
    case PDE_GENERIC_NETWORK_ADAPTER:
        if (!(sdkName = prlsdkGetStringParamVar(PrlVmDevNet_GetHostInterfaceName,
                                                dev)))
            goto cleanup;

        if (bootIndex >= def->nnets) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Can't find network boot device for index: %d"),
                           bootIndex);
            goto cleanup;
        }

        if (STRNEQ(sdkName, def->nets[bootIndex]->ifname))
            VIR_WARN("Unrepresentable boot order configuration");

        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unexpected device type %d"), sdkType);
        goto cleanup;
    }

    ret = 0;

 cleanup:

    VIR_FREE(sdkName);
    PrlHandle_Free(dev);
    VIR_FREE(dst);
    return ret;
}

static int
prlsdkConvertBootOrderVm(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    int ret = -1;
    PRL_RESULT pret;
    PRL_UINT32 bootNum;
    PRL_HANDLE bootDev = PRL_INVALID_HANDLE;
    PRL_BOOL inUse;
    PRL_DEVICE_TYPE sdkType;
    virDomainBootOrder type;
    PRL_UINT32 prevBootIndex = 0, bootIndex, sdkIndex;
    int bootUsage[VIR_DOMAIN_BOOT_LAST] = { 0 };
    size_t i;

    pret = PrlVmCfg_GetBootDevCount(sdkdom, &bootNum);
    prlsdkCheckRetExit(pret, -1);

    def->os.nBootDevs = 0;

    if (bootNum > VIR_DOMAIN_MAX_BOOT_DEVS) {
        bootNum = VIR_DOMAIN_MAX_BOOT_DEVS;
        VIR_WARN("Too many boot devices");
    }

    for (i = 0; i < bootNum; ++i) {
        pret = PrlVmCfg_GetBootDev(sdkdom, i, &bootDev);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlBootDev_IsInUse(bootDev, &inUse);
        prlsdkCheckRetGoto(pret, cleanup);

        if (!inUse) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Boot ordering with disabled items is not supported"));
            goto cleanup;
        }

        pret = PrlBootDev_GetSequenceIndex(bootDev, &bootIndex);
        prlsdkCheckRetGoto(pret, cleanup);

        /* bootIndex is started from 1 */
        if (bootIndex <= prevBootIndex) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Unsupported boot order configuration"));
            goto cleanup;
        }
        prevBootIndex = bootIndex;

        pret = PrlBootDev_GetType(bootDev, &sdkType);
        prlsdkCheckRetGoto(pret, cleanup);

        if (sdkType == PDE_FLOPPY_DISK) {
            VIR_WARN("Skipping floppy from boot order.");
            continue;
        }

        switch (sdkType) {
        case PDE_OPTICAL_DISK:
            type = VIR_DOMAIN_BOOT_CDROM;
            break;
        case PDE_HARD_DISK:
            type = VIR_DOMAIN_BOOT_DISK;
            break;
        case PDE_GENERIC_NETWORK_ADAPTER:
            type = VIR_DOMAIN_BOOT_NET;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unexpected boot device type %i"), sdkType);
            goto cleanup;
        }

        pret = PrlBootDev_GetIndex(bootDev, &sdkIndex);
        prlsdkCheckRetGoto(pret, cleanup);

        if (prlsdkBootOrderCheck(sdkdom, sdkType, sdkIndex, def, bootUsage[type]) < 0)
            goto cleanup;

        bootUsage[type]++;
        def->os.bootDevs[def->os.nBootDevs++] = type;

        PrlHandle_Free(bootDev);
        bootDev = PRL_INVALID_HANDLE;
    }

    ret = 0;

 cleanup:
    PrlHandle_Free(bootDev);
    return ret;
}

/* if dom is NULL adds new domain into domain list
 * if dom not NULL updates given locked dom object.
 *
 * Returned object is locked and referenced.
 */

static virDomainObjPtr
prlsdkLoadDomain(vzDriverPtr driver,
                 PRL_HANDLE sdkdom,
                 virDomainObjPtr dom)
{
    virDomainDefPtr def = NULL;
    vzDomObjPtr pdom = NULL;
    VIRTUAL_MACHINE_STATE domainState;

    PRL_RESULT pret;
    PRL_UINT32 ram;
    PRL_UINT32 envId;
    PRL_VM_AUTOSTART_OPTION autostart;
    PRL_HANDLE job;
    char uuidstr[VIR_UUID_STRING_BRACED_BUFLEN];

    if (!(def = virDomainDefNew()))
        goto error;

    if (!(def->name = prlsdkGetStringParamVar(PrlVmCfg_GetName, sdkdom)))
        goto error;

    pret = prlsdkGetStringParamBuf(PrlVmCfg_GetUuid,
                                   sdkdom, uuidstr, sizeof(uuidstr));
    prlsdkCheckRetGoto(pret, error);

    if (prlsdkUUIDParse(uuidstr, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain UUID is malformed or empty"));
        goto error;
    }

    def->virtType = VIR_DOMAIN_VIRT_VZ;

    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY;

    /* get RAM parameters */
    pret = PrlVmCfg_GetRamSize(sdkdom, &ram);
    prlsdkCheckRetGoto(pret, error);
    virDomainDefSetMemoryTotal(def, ram << 10); /* RAM size obtained in Mbytes,
                                                     convert to Kbytes */
    def->mem.cur_balloon = ram << 10;

    if (prlsdkConvertCpuInfo(sdkdom, def, driver->xmlopt) < 0)
        goto error;

    if (prlsdkConvertCpuMode(sdkdom, def) < 0)
        goto error;

    if (prlsdkConvertDomainType(sdkdom, def) < 0)
        goto error;

    if (prlsdkAddVNCInfo(sdkdom, def) < 0)
        goto error;

    /* depends on prlsdkAddVNCInfo */
    if (prlsdkAddDomainHardware(driver, sdkdom, def) < 0)
        goto error;

    /* depends on prlsdkAddDomainHardware */
    if (!IS_CT(def) && prlsdkConvertBootOrderVm(sdkdom, def) < 0)
        goto error;

    pret = PrlVmCfg_GetEnvId(sdkdom, &envId);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlVmCfg_GetAutoStart(sdkdom, &autostart);
    prlsdkCheckRetGoto(pret, error);
    if (autostart != PAO_VM_START_ON_LOAD &&
        autostart != PAO_VM_START_MANUAL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown autostart mode: %X"), autostart);
        goto error;
    }

    if (prlsdkGetDomainState(dom, sdkdom, &domainState) < 0)
        goto error;

    if (!IS_CT(def) && virDomainDefAddImplicitDevices(def) < 0)
        goto error;

    if (def->ngraphics > 0) {
        int bus = IS_CT(def) ? VIR_DOMAIN_INPUT_BUS_PARALLELS :
                               VIR_DOMAIN_INPUT_BUS_PS2;

        if (virDomainDefMaybeAddInput(def,
                                      VIR_DOMAIN_INPUT_TYPE_MOUSE,
                                      bus) < 0)
            goto error;

        if (virDomainDefMaybeAddInput(def,
                                      VIR_DOMAIN_INPUT_TYPE_KBD,
                                      bus) < 0)
            goto error;
    }

    if (!dom) {
        virDomainObjPtr olddom = NULL;

        job = PrlVm_SubscribeToPerfStats(sdkdom, NULL);
        if (PRL_FAILED(waitJob(job)))
            goto error;

        virObjectLock(driver);
        if (!(olddom = virDomainObjListFindByUUIDRef(driver->domains, def->uuid)))
            dom = virDomainObjListAdd(driver->domains, def, driver->xmlopt, 0, NULL);
        virObjectUnlock(driver);

        if (olddom) {
            virDomainDefFree(def);
            return olddom;
        } else if (!dom) {
            goto error;
        }

        virObjectRef(dom);
        pdom = dom->privateData;
        pdom->sdkdom = sdkdom;
        PrlHandle_AddRef(sdkdom);
        dom->persistent = 1;
    } else {
        /* assign new virDomainDef without any checks
         * we can't use virDomainObjAssignDef, because it checks
         * for state and domain name */
        virDomainDefFree(dom->def);
        dom->def = def;
    }

    pdom = dom->privateData;
    pdom->id = envId;

    prlsdkConvertDomainState(domainState, envId, dom);

    if (autostart == PAO_VM_START_ON_LOAD)
        dom->autostart = 1;
    else
        dom->autostart = 0;

    return dom;

 error:
    virDomainDefFree(def);
    return NULL;
}

int
prlsdkLoadDomains(vzDriverPtr driver)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result;
    PRL_HANDLE sdkdom = PRL_INVALID_HANDLE;
    PRL_UINT32 paramsCount;
    PRL_RESULT pret;
    size_t i = 0;
    virDomainObjPtr dom;

    job = PrlSrv_GetVmListEx(driver->server, PVTF_VM | PVTF_CT);

    if (PRL_FAILED(getJobResult(job, &result)))
        return -1;

    pret = PrlResult_GetParamsCount(result, &paramsCount);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < paramsCount; i++) {
        pret = PrlResult_GetParamByIndex(result, i, &sdkdom);
        prlsdkCheckRetGoto(pret, error);

        dom = prlsdkLoadDomain(driver, sdkdom, NULL);
        virDomainObjEndAPI(&dom);

        PrlHandle_Free(sdkdom);
        sdkdom = PRL_INVALID_HANDLE;
    }

    PrlHandle_Free(result);
    return 0;

 error:
    PrlHandle_Free(sdkdom);
    PrlHandle_Free(result);
    return -1;
}

virDomainObjPtr
prlsdkAddDomainByUUID(vzDriverPtr driver, const unsigned char *uuid)
{
    PRL_HANDLE sdkdom;
    virDomainObjPtr dom;

    sdkdom = prlsdkSdkDomainLookupByUUID(driver, uuid);
    if (sdkdom == PRL_INVALID_HANDLE)
        return NULL;

    dom = prlsdkLoadDomain(driver, sdkdom, NULL);

    PrlHandle_Free(sdkdom);
    return dom;
}

virDomainObjPtr
prlsdkAddDomainByName(vzDriverPtr driver, const char *name)
{
    PRL_HANDLE sdkdom;
    virDomainObjPtr dom;

    sdkdom = prlsdkSdkDomainLookupByName(driver, name);
    if (sdkdom == PRL_INVALID_HANDLE)
        return NULL;

    dom = prlsdkLoadDomain(driver, sdkdom, NULL);

    PrlHandle_Free(sdkdom);
    return dom;
}

int
prlsdkUpdateDomain(vzDriverPtr driver, virDomainObjPtr dom)
{
    PRL_HANDLE job;
    vzDomObjPtr pdom = dom->privateData;

    job = PrlVm_RefreshConfig(pdom->sdkdom);
    if (waitDomainJob(job, dom))
        return -1;

    return prlsdkLoadDomain(driver, pdom->sdkdom, dom) ? 0 : -1;
}

static void
prlsdkSendEvent(vzDriverPtr driver,
                virDomainObjPtr dom,
                virDomainEventType lvEventType,
                int lvEventTypeDetails)
{
    virObjectEventPtr event;

    event = virDomainEventLifecycleNewFromObj(dom,
                                              lvEventType,
                                              lvEventTypeDetails);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
}

static void
prlsdkNewStateToEvent(VIRTUAL_MACHINE_STATE domainState,
                      virDomainEventType *lvEventType,
                      int *lvEventTypeDetails)
{
    /* We skip all intermediate states here, because
     * libvirt doesn't have correspoding event types for
     * them */
    switch (domainState) {
    case VMS_STOPPED:
    case VMS_MOUNTED:
        *lvEventType = VIR_DOMAIN_EVENT_STOPPED;
        *lvEventTypeDetails = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        break;
    case VMS_RUNNING:
        *lvEventType = VIR_DOMAIN_EVENT_STARTED;
        *lvEventTypeDetails = VIR_DOMAIN_EVENT_STARTED_BOOTED;
        break;
    case VMS_PAUSED:
        *lvEventType = VIR_DOMAIN_EVENT_SUSPENDED;
        *lvEventTypeDetails = VIR_DOMAIN_EVENT_SUSPENDED_PAUSED;
        break;
    case VMS_SUSPENDED:
        *lvEventType = VIR_DOMAIN_EVENT_STOPPED;
        *lvEventTypeDetails = VIR_DOMAIN_EVENT_STOPPED_SAVED;
        break;
    default:
        VIR_DEBUG("Skip sending event about changing state to %X",
                  domainState);
        break;
    }
}

static void
prlsdkHandleVmStateEvent(vzDriverPtr driver,
                         PRL_HANDLE prlEvent,
                         unsigned char *uuid)
{
    PRL_RESULT pret = PRL_ERR_FAILURE;
    PRL_HANDLE eventParam = PRL_INVALID_HANDLE;
    PRL_INT32 domainState;
    virDomainObjPtr dom = NULL;
    vzDomObjPtr pdom;
    virDomainEventType lvEventType = 0;
    int lvEventTypeDetails = 0;

    dom = virDomainObjListFindByUUID(driver->domains, uuid);
    if (dom == NULL)
        return;

    pret = PrlEvent_GetParamByName(prlEvent, "vminfo_vm_state", &eventParam);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlEvtPrm_ToInt32(eventParam, &domainState);
    prlsdkCheckRetGoto(pret, cleanup);

    pdom = dom->privateData;

    prlsdkConvertDomainState(domainState, pdom->id, dom);

    prlsdkNewStateToEvent(domainState,
                          &lvEventType,
                          &lvEventTypeDetails);

    prlsdkSendEvent(driver, dom, lvEventType, lvEventTypeDetails);

 cleanup:
    PrlHandle_Free(eventParam);
    virObjectUnlock(dom);
    return;
}

static void
prlsdkHandleVmConfigEvent(vzDriverPtr driver,
                          unsigned char *uuid)
{
    virDomainObjPtr dom = NULL;
    bool job = false;

    dom = virDomainObjListFindByUUIDRef(driver->domains, uuid);
    if (dom == NULL)
        return;

    if (vzDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (dom->removing)
        goto cleanup;

    if (prlsdkUpdateDomain(driver, dom) < 0)
        goto cleanup;

    prlsdkSendEvent(driver, dom, VIR_DOMAIN_EVENT_DEFINED,
                    VIR_DOMAIN_EVENT_DEFINED_UPDATED);

 cleanup:
    if (job)
        vzDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);
    return;
}

static void
prlsdkHandleVmAddedEvent(vzDriverPtr driver,
                         unsigned char *uuid)
{
    virDomainObjPtr dom = NULL;

    if (!(dom = virDomainObjListFindByUUIDRef(driver->domains, uuid)) &&
        !(dom = prlsdkAddDomainByUUID(driver, uuid)))
        goto cleanup;

    prlsdkSendEvent(driver, dom, VIR_DOMAIN_EVENT_DEFINED,
                    VIR_DOMAIN_EVENT_DEFINED_ADDED);

 cleanup:
    virDomainObjEndAPI(&dom);
    return;
}

static void
prlsdkHandleVmRemovedEvent(vzDriverPtr driver,
                           unsigned char *uuid)
{
    virDomainObjPtr dom = NULL;

    dom = virDomainObjListFindByUUID(driver->domains, uuid);
    /* domain was removed from the list from the libvirt
     * API function in current connection */
    if (dom == NULL)
        return;

    prlsdkSendEvent(driver, dom, VIR_DOMAIN_EVENT_UNDEFINED,
                    VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    virDomainObjListRemove(driver->domains, dom);
    return;
}

#define PARALLELS_STATISTICS_DROP_COUNT 3

static void
prlsdkHandlePerfEvent(vzDriverPtr driver,
                      PRL_HANDLE event,
                      unsigned char *uuid)
{
    virDomainObjPtr dom = NULL;
    vzDomObjPtr privdom = NULL;

    if (!(dom = virDomainObjListFindByUUID(driver->domains, uuid))) {
        PrlHandle_Free(event);
        return;
    }

    privdom = dom->privateData;
    PrlHandle_Free(privdom->stats);
    privdom->stats = event;

    virObjectUnlock(dom);
}

static void
prlsdkHandleMigrationProgress(vzDriverPtr driver,
                              PRL_HANDLE event,
                              unsigned char *uuid)
{
    virDomainObjPtr dom = NULL;
    vzDomObjPtr privdom = NULL;
    PRL_UINT32 progress;
    PRL_HANDLE param = PRL_INVALID_HANDLE;
    PRL_RESULT pret;

    if (!(dom = virDomainObjListFindByUUID(driver->domains, uuid)))
        return;

    pret = PrlEvent_GetParam(event, 0, &param);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlEvtPrm_ToUint32(param, &progress);
    prlsdkCheckRetGoto(pret, cleanup);

    privdom = dom->privateData;
    privdom->job.progress = progress;

 cleanup:
    PrlHandle_Free(param);
    virObjectUnlock(dom);
}

static PRL_RESULT
prlsdkEventsHandler(PRL_HANDLE prlEvent, PRL_VOID_PTR opaque)
{
    vzDriverPtr driver = opaque;
    PRL_RESULT pret = PRL_ERR_FAILURE;
    PRL_HANDLE_TYPE handleType;
    char uuidstr[VIR_UUID_STRING_BRACED_BUFLEN];
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRL_EVENT_TYPE prlEventType;

    pret = PrlHandle_GetType(prlEvent, &handleType);
    prlsdkCheckRetGoto(pret, cleanup);

    /* Currently, there is no need to handle anything but events */
    if (handleType != PHT_EVENT)
        goto cleanup;

    if (driver == NULL)
        goto cleanup;

    pret = prlsdkGetStringParamBuf(PrlEvent_GetIssuerId,
                                   prlEvent, uuidstr, sizeof(uuidstr));
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlEvent_GetType(prlEvent, &prlEventType);
    prlsdkCheckRetGoto(pret, cleanup);

    if (prlsdkUUIDParse(uuidstr, uuid) < 0) {
        VIR_DEBUG("Skipping event type %d", prlEventType);
        goto cleanup;
    }

    switch (prlEventType) {
    case PET_DSP_EVT_VM_STATE_CHANGED:
        prlsdkHandleVmStateEvent(driver, prlEvent, uuid);
        break;
    case PET_DSP_EVT_VM_CONFIG_CHANGED:
        prlsdkHandleVmConfigEvent(driver, uuid);
        break;
    case PET_DSP_EVT_VM_CREATED:
    case PET_DSP_EVT_VM_ADDED:
        prlsdkHandleVmAddedEvent(driver, uuid);
        break;
    case PET_DSP_EVT_VM_DELETED:
    case PET_DSP_EVT_VM_UNREGISTERED:
        prlsdkHandleVmRemovedEvent(driver, uuid);
        break;
    case PET_DSP_EVT_VM_PERFSTATS:
        prlsdkHandlePerfEvent(driver, prlEvent, uuid);
        /* above function takes own of event */
        prlEvent = PRL_INVALID_HANDLE;
        break;
    case PET_DSP_EVT_DISP_CONNECTION_CLOSED:
        vzDestroyDriverConnection();
        break;
    case PET_DSP_EVT_VM_MIGRATE_PROGRESS_CHANGED:
        prlsdkHandleMigrationProgress(driver, prlEvent, uuid);
        break;
    default:
        VIR_DEBUG("Skipping event of type %d", prlEventType);
    }

 cleanup:
    PrlHandle_Free(prlEvent);
    return PRL_ERR_SUCCESS;
}

int prlsdkSubscribeToPCSEvents(vzDriverPtr driver)
{
    PRL_RESULT pret = PRL_ERR_UNINITIALIZED;

    pret = PrlSrv_RegEventHandler(driver->server,
                                  prlsdkEventsHandler,
                                  driver);
    prlsdkCheckRetGoto(pret, error);
    return 0;

 error:
    return -1;
}

void prlsdkUnsubscribeFromPCSEvents(vzDriverPtr driver)
{
    PRL_RESULT ret = PRL_ERR_UNINITIALIZED;
    ret = PrlSrv_UnregEventHandler(driver->server,
                                   prlsdkEventsHandler,
                                   driver);
    if (PRL_FAILED(ret))
        logPrlError(ret);
}

int prlsdkStart(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_StartEx(privdom->sdkdom, PSM_VM_START, 0);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkKill(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_StopEx(privdom->sdkdom, PSM_KILL, 0);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkStop(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_StopEx(privdom->sdkdom, PSM_SHUTDOWN, 0);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkPause(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_Pause(privdom->sdkdom, false);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkResume(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_Resume(privdom->sdkdom);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkSuspend(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_Suspend(privdom->sdkdom);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkRestart(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_Restart(privdom->sdkdom);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

int prlsdkReset(virDomainObjPtr dom)
{
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    PRL_RESULT pret;

    job = PrlVm_Reset(privdom->sdkdom);
    if (PRL_FAILED(pret = waitDomainJob(job, dom))) {
        prlsdkConvertError(pret);
        return -1;
    }

    return 0;
}

static void
prlsdkConvertError(PRL_RESULT pret)
{
    virErrorNumber virerr;

    switch (pret) {
    case PRL_ERR_DISP_VM_IS_NOT_STARTED:
    case PRL_ERR_DISP_VM_IS_NOT_STOPPED:
    case PRL_ERR_INVALID_ACTION_REQUESTED:
    case PRL_ERR_UNIMPLEMENTED:
        virerr = VIR_ERR_OPERATION_INVALID;
        break;
    default:
        virerr = VIR_ERR_OPERATION_FAILED;
    }

    virResetLastError();
    virReportError(virerr, "%s", _("Can't change domain state."));
}

static int
prlsdkCheckUnsupportedParams(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    size_t i;
    PRL_VM_TYPE vmType;
    PRL_RESULT pret;
    virDomainNumatuneMemMode memMode;
    int bus = IS_CT(def) ? VIR_DOMAIN_INPUT_BUS_PARALLELS :
                           VIR_DOMAIN_INPUT_BUS_PS2;

    if (def->title) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("titles are not supported by vz driver"));
        return -1;
    }

    if (def->blkio.ndevices > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("blkio parameters are not supported "
                         "by vz driver"));
        return -1;
    }

    if (virDomainDefGetMemoryTotal(def) != def->mem.cur_balloon) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing balloon parameters is not supported "
                         "by vz driver"));
        return -1;
    }

    if (virDomainDefGetMemoryTotal(def) % (1 << 10) != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Memory size should be multiple of 1Mb."));
        return -1;
    }

    if (def->mem.nhugepages ||
        virMemoryLimitIsSet(def->mem.hard_limit) ||
        virMemoryLimitIsSet(def->mem.soft_limit) ||
        def->mem.min_guarantee ||
        virMemoryLimitIsSet(def->mem.swap_hard_limit)) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Memory parameter is not supported "
                         "by vz driver"));
        return -1;
    }

    if (virDomainDefHasVcpusOffline(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpus must be equal to maxvcpus"));
        return -1;
    }

    if (def->placement_mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing cpu placement mode is not supported "
                         "by vz driver"));
        return -1;
    }

    if (def->cputune.shares ||
        def->cputune.sharesSpecified ||
        def->cputune.period ||
        def->cputune.quota) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cputune is not supported by vz driver"));
        return -1;
    }

    for (i = 0; i < virDomainDefGetVcpusMax(def); i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(def, i);

        if (vcpu->cpumask &&
            !virBitmapEqual(def->cpumask, vcpu->cpumask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vcpupin cpumask differs from default cpumask"));
            return -1;
        }
    }


    /*
     * Though we don't support NUMA configuration at the moment
     * virDomainDefPtr always contain non zero NUMA configuration
     * So, just make sure this configuration does't differ from auto generated.
     */
    if ((virDomainNumatuneGetMode(def->numa, -1, &memMode) == 0 &&
         memMode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) ||
        virDomainNumatuneHasPerNodeBinding(def->numa)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("numa parameters are not supported "
                         "by vz driver"));
        return -1;
    }

    if (def->onReboot != VIR_DOMAIN_LIFECYCLE_RESTART ||
        def->onPoweroff != VIR_DOMAIN_LIFECYCLE_DESTROY ||
        def->onCrash != VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("on_reboot, on_poweroff and on_crash parameters "
                         "are not supported by vz driver"));
        return -1;
    }

    /* we fill only type and arch fields in vzLoadDomain for
     * hvm type and also init for containers, so we can check that all
     * other paramenters are null and boot devices config is default */

    if (def->os.machine != NULL || def->os.bootmenu != 0 ||
        def->os.kernel != NULL || def->os.initrd != NULL ||
        def->os.cmdline != NULL || def->os.root != NULL ||
        def->os.loader != NULL || def->os.bootloader != NULL ||
        def->os.bootloaderArgs != NULL || def->os.smbios_mode != 0 ||
        def->os.bios.useserial != 0) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing OS parameters is not supported "
                         "by vz driver"));
        return -1;
    }

    pret = PrlVmCfg_GetVmType(sdkdom, &vmType);
    if (PRL_FAILED(pret)) {
        logPrlError(pret);
        return -1;
    }

    if (!(vmType == PVT_VM && !IS_CT(def)) &&
        !(vmType == PVT_CT && IS_CT(def))) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing OS type is not supported "
                         "by vz driver"));
        return -1;
    }

    if (!IS_CT(def)) {
        if (def->os.init != NULL || def->os.initargv != NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported OS parameters"));
            return -1;
        }
    } else {
        if (def->os.nBootDevs != 0 ||
            STRNEQ_NULLABLE(def->os.init, "/sbin/init") ||
            (def->os.initargv != NULL && def->os.initargv[0] != NULL)) {

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported OS parameters"));
            return -1;
        }
    }

    if (def->emulator) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing emulator is not supported "
                         "by vz driver"));
        return -1;
    }

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        if (def->features[i]) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("changing features is not supported "
                             "by vz driver"));
            return -1;
        }
    }

    if (def->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_UTC ||
        def->clock.ntimers != 0) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing clock parameters is not supported "
                         "by vz driver"));
        return -1;
    }

    if (!IS_CT(def) && def->nfss != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Filesystems in VMs are not supported "
                         "by vz driver"));
        return -1;
    }

    if (def->nsounds != 0 || def->nhostdevs != 0 ||
        def->nredirdevs != 0 || def->nsmartcards != 0 ||
        def->nparallels || def->nchannels != 0 ||
        def->nleases != 0 || def->nhubs != 0) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("changing devices parameters is not supported "
                         "by vz driver"));
        return -1;
    }

    /* check we have only default input devices */
    if (def->ngraphics > 0) {
        if (def->ninputs != 2 ||
            def->inputs[0]->bus != bus ||
            def->inputs[1]->bus != bus ||
            !((def->inputs[0]->type == VIR_DOMAIN_INPUT_TYPE_MOUSE &&
               def->inputs[1]->type == VIR_DOMAIN_INPUT_TYPE_KBD) ||
              (def->inputs[0]->type == VIR_DOMAIN_INPUT_TYPE_KBD &&
               def->inputs[1]->type == VIR_DOMAIN_INPUT_TYPE_MOUSE))) {

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported input device configuration"));
            return -1;
        }
    } else if (def->ninputs != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("input devices without vnc are not supported"));
        return -1;
    }

    return 0;
}

static int prlsdkClearDevices(PRL_HANDLE sdkdom)
{
    PRL_RESULT pret;
    PRL_UINT32 n, i;
    PRL_HANDLE devList;
    PRL_HANDLE dev;
    int ret = -1;

    pret = PrlVmCfg_GetAllDevices(sdkdom, &devList);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlHndlList_GetItemsCount(devList, &n);
    prlsdkCheckRetGoto(pret, cleanup);

    for (i = 0; i < n; i++) {
        pret = PrlHndlList_GetItem(devList, i, &dev);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlVmDev_Remove(dev);
        PrlHandle_Free(dev);
    }

    ret = 0;
 cleanup:
    PrlHandle_Free(devList);
    return ret;
}

static int
prlsdkRemoveBootDevices(PRL_HANDLE sdkdom)
{
    PRL_RESULT pret;
    PRL_UINT32 i, devCount;
    PRL_HANDLE dev = PRL_INVALID_HANDLE;
    PRL_DEVICE_TYPE devType;

    pret = PrlVmCfg_GetBootDevCount(sdkdom, &devCount);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < devCount; i++) {

        /* always get device by index 0, because device list resort after delete */
        pret = PrlVmCfg_GetBootDev(sdkdom, 0, &dev);
        prlsdkCheckRetGoto(pret, error);

        pret = PrlBootDev_GetType(dev, &devType);
        prlsdkCheckRetGoto(pret, error);

        pret = PrlBootDev_Remove(dev);
        prlsdkCheckRetGoto(pret, error);
    }

    return 0;

 error:
    return -1;
}

static int
prlsdkAddDeviceToBootList(PRL_HANDLE sdkdom,
                          PRL_UINT32 devIndex,
                          PRL_DEVICE_TYPE devType,
                          PRL_UINT32 bootSequence)
{
    PRL_RESULT pret;
    PRL_HANDLE bootDev = PRL_INVALID_HANDLE;

    pret = PrlVmCfg_CreateBootDev(sdkdom, &bootDev);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlBootDev_SetIndex(bootDev, devIndex);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlBootDev_SetType(bootDev, devType);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlBootDev_SetSequenceIndex(bootDev, bootSequence);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlBootDev_SetInUse(bootDev, PRL_TRUE);
    prlsdkCheckRetGoto(pret, error);

    return 0;

 error:
    if (bootDev != PRL_INVALID_HANDLE)
        PrlBootDev_Remove(bootDev);

    return -1;
}

static int prlsdkCheckVideoUnsupportedParams(virDomainDefPtr def)
{
    virDomainVideoDefPtr v;

    if (IS_CT(def)) {
        if (def->nvideos == 0) {
            return 0;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Video adapters are not supported "
                             "int containers."));
            return -1;
        }
    } else {
        if (def->nvideos != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vz driver supports "
                             "only one video adapter."));
            return -1;
        }
    }

    v = def->videos[0];

    if (v->type != VIR_DOMAIN_VIDEO_TYPE_VGA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver supports "
                         "only VGA video adapters."));
        return -1;
    }

    if (v->heads != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "multihead video adapters."));
        return -1;
    }

    if (v->accel != NULL && (v->accel->accel2d || v->accel->accel3d)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "setting video acceleration parameters."));
        return -1;
    }

    return 0;
}

static int prlsdkCheckSerialUnsupportedParams(virDomainChrDefPtr chr)
{
    if (chr->deviceType != VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified character device type is not supported "
                         "by vz driver."));
        return -1;
    }

    if (chr->targetTypeAttr) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified character device target type is not "
                         "supported by vz driver."));
        return -1;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_DEV &&
        chr->source->type != VIR_DOMAIN_CHR_TYPE_FILE &&
        chr->source->type != VIR_DOMAIN_CHR_TYPE_UNIX &&
        chr->source->type != VIR_DOMAIN_CHR_TYPE_TCP &&
        chr->source->type != VIR_DOMAIN_CHR_TYPE_UDP) {


        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified character device source type is not "
                         "supported by vz driver."));
        return -1;
    }

    if (chr->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting device info for character devices is not "
                         "supported by vz driver."));
        return -1;
    }

    if (chr->nseclabels > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting security labels is not "
                         "supported by vz driver."));
        return -1;
    }

   if (chr->source->type == VIR_DOMAIN_CHR_TYPE_TCP &&
        chr->source->data.tcp.protocol != VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Protocol '%s' is not supported for "
                         "tcp character device."),
                       virDomainChrTcpProtocolTypeToString(chr->source->data.tcp.protocol));
        return -1;
    }

    if (chr->source->type == VIR_DOMAIN_CHR_TYPE_UDP &&
        (STRNEQ(chr->source->data.udp.bindHost,
                chr->source->data.udp.connectHost) ||
         STRNEQ(chr->source->data.udp.bindService,
                chr->source->data.udp.connectService))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Different bind and connect parameters for "
                         "udp character device is not supported."));
        return -1;
    }

    return 0;
}

static int prlsdkCheckNetUnsupportedParams(virDomainNetDefPtr net)
{
    if (net->type != VIR_DOMAIN_NET_TYPE_NETWORK &&
        net->type != VIR_DOMAIN_NET_TYPE_BRIDGE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified network adapter type is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->backend.tap || net->backend.vhost) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface backend parameters are not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->data.network.portgroup) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Virtual network portgroups are not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->tune.sndbuf_specified) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting interface sndbuf is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->script) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting interface script is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->ifname_guest) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting guest interface name is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting device info for network devices is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->filter) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting network filter is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->bandwidth) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting network bandwidth is not "
                         "supported by vz driver."));
        return -1;
    }

    if (net->vlan.trunk) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting up vlans is not "
                         "supported by vz driver."));
        return -1;
    }

    return 0;
}

static int prlsdkCheckFSUnsupportedParams(virDomainFSDefPtr fs)
{
    if (fs->type != VIR_DOMAIN_FS_TYPE_FILE &&
        fs->type != VIR_DOMAIN_FS_TYPE_VOLUME) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only file based or volume based filesystems "
                         "are supported by vz driver."));
        return -1;
    }

    if (fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only ploop fs driver is "
                         "supported by vz driver."));
        return -1;
    }

    if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Changing fs access mode is not "
                         "supported by vz driver."));
        return -1;
    }

    if (fs->wrpolicy != VIR_DOMAIN_FS_WRPOLICY_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Changing fs write policy is not "
                         "supported by vz driver."));
        return -1;
    }

    if (fs->format != VIR_STORAGE_FILE_PLOOP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only ploop disk images are "
                         "supported by vz driver."));
        return -1;
    }

    if (fs->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting readonly for filesystems is "
                         "not supported by vz driver."));
        return -1;
    }

    if (fs->space_hard_limit || fs->space_soft_limit) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting fs quotas is not "
                         "supported by vz driver."));
        return -1;
    }

    return 0;
}

static int prlsdkApplyGraphicsParams(PRL_HANDLE sdkdom,
                                     virDomainGraphicsDefPtr gr)
{
    virDomainGraphicsListenDefPtr glisten;
    PRL_RESULT pret;
    int ret  = -1;

    if (!gr) {
        pret = PrlVmCfg_SetVNCMode(sdkdom, PRD_DISABLED);
        prlsdkCheckRetExit(pret, -1);
        return 0;
    }

    pret = PrlVmCfg_SetVNCPassword(sdkdom, gr->data.vnc.auth.passwd ? : "");
    prlsdkCheckRetExit(pret, -1);

    if (gr->data.vnc.autoport) {
        pret = PrlVmCfg_SetVNCMode(sdkdom, PRD_AUTO);
        prlsdkCheckRetGoto(pret, cleanup);
    } else {
        pret = PrlVmCfg_SetVNCMode(sdkdom, PRD_MANUAL);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlVmCfg_SetVNCPort(sdkdom, gr->data.vnc.port);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    glisten = virDomainGraphicsGetListen(gr, 0);
    pret = PrlVmCfg_SetVNCHostName(sdkdom, glisten && glisten->address ?
                                           glisten->address : "127.0.0.1");
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;
 cleanup:
    return ret;
}

static int prlsdkApplyVideoParams(PRL_HANDLE sdkdom ATTRIBUTE_UNUSED, virDomainDefPtr def)
{
    PRL_RESULT pret;

    if (def->nvideos == 0)
        return 0;

    if (IS_CT(def)) {
        /* ignore video parameters */
        return 0;
    }

    if (prlsdkCheckVideoUnsupportedParams(def))
        return -1;

    pret = PrlVmCfg_SetVideoRamSize(sdkdom, def->videos[0]->vram >> 10);
    prlsdkCheckRetGoto(pret, error);

    return 0;
 error:
    return -1;
}

static int prlsdkAddSerial(PRL_HANDLE sdkdom, virDomainChrDefPtr chr)
{
    PRL_RESULT pret;
    PRL_HANDLE sdkchr = PRL_INVALID_HANDLE;
    PRL_VM_DEV_EMULATION_TYPE emutype;
    PRL_SERIAL_PORT_SOCKET_OPERATION_MODE socket_mode = PSP_SERIAL_SOCKET_SERVER;
    char *path;
    char *url = NULL;
    int ret = -1;

    if (prlsdkCheckSerialUnsupportedParams(chr) < 0)
        return -1;

    pret = PrlVmCfg_CreateVmDev(sdkdom, PDE_SERIAL_PORT, &sdkchr);
    prlsdkCheckRetGoto(pret, cleanup);

    switch (chr->source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
        emutype = PDT_USE_REAL_DEVICE;
        path = chr->source->data.file.path;
        break;
    case VIR_DOMAIN_CHR_TYPE_FILE:
        emutype = PDT_USE_OUTPUT_FILE;
        path = chr->source->data.file.path;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        emutype = PDT_USE_SERIAL_PORT_SOCKET_MODE;
        path = chr->source->data.nix.path;
        if (!chr->source->data.nix.listen)
            socket_mode = PSP_SERIAL_SOCKET_CLIENT;
        break;
    case VIR_DOMAIN_CHR_TYPE_TCP:
        emutype = PDT_USE_TCP;
        if (virAsprintf(&url, "%s:%s",
                        chr->source->data.tcp.host,
                        chr->source->data.tcp.service) < 0)
            goto cleanup;
        if (!chr->source->data.tcp.listen)
            socket_mode = PSP_SERIAL_SOCKET_CLIENT;
        path = url;
        break;
    case VIR_DOMAIN_CHR_TYPE_UDP:
        emutype = PDT_USE_UDP;
        if (virAsprintf(&url, "%s:%s",
                        chr->source->data.udp.bindHost,
                        chr->source->data.udp.bindService) < 0)
            goto cleanup;
        path = url;
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "specified serial source type."));
        goto cleanup;
    }

    pret = PrlVmDev_SetEmulatedType(sdkchr, emutype);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetSysName(sdkchr, path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetFriendlyName(sdkchr, path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDevSerial_SetSocketMode(sdkchr, socket_mode);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetEnabled(sdkchr, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetIndex(sdkchr, chr->target.port);
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;
 cleanup:
    PrlHandle_Free(sdkchr);
    VIR_FREE(url);
    return ret;
}

#define PRL_MAC_STRING_BUFNAME  13

static const char * prlsdkFormatMac(virMacAddrPtr mac, char *macstr)
{
    snprintf(macstr, PRL_MAC_STRING_BUFNAME,
             "%02X%02X%02X%02X%02X%02X",
             mac->addr[0], mac->addr[1], mac->addr[2],
             mac->addr[3], mac->addr[4], mac->addr[5]);
    macstr[PRL_MAC_STRING_BUFNAME - 1] = '\0';
    return macstr;
}

static int prlsdkConfigureGateways(PRL_HANDLE sdknet, virDomainNetDefPtr net)
{
    int ret = -1;
    size_t i;
    virNetDevIPRoutePtr route4 = NULL, route6 = NULL;
    char *gw4 = NULL, *gw6 = NULL;
    PRL_RESULT pret;

    for (i = 0; i < net->guestIP.nroutes; i++) {
        virSocketAddrPtr addrdst, gateway;
        virSocketAddr zero;

        addrdst = virNetDevIPRouteGetAddress(net->guestIP.routes[i]);
        gateway = virNetDevIPRouteGetGateway(net->guestIP.routes[i]);

        ignore_value(virSocketAddrParse(&zero,
                                (VIR_SOCKET_ADDR_IS_FAMILY(addrdst, AF_INET)
                                 ? VIR_SOCKET_ADDR_IPV4_ALL
                                 : VIR_SOCKET_ADDR_IPV6_ALL),
                                VIR_SOCKET_ADDR_FAMILY(addrdst)));
        /* virSocketAddrParse raises an error
         * and we are not going to report it, reset it expicitly*/
        virResetLastError();

        if (!virSocketAddrEqual(addrdst, &zero)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Support only default gateway"));
            return -1;
        }

        switch (VIR_SOCKET_ADDR_FAMILY(gateway)) {
        case AF_INET:
            if (route4) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Support only one IPv4 default gateway"));
                return -1;
            }

            route4 = net->guestIP.routes[i];

            break;
        case AF_INET6:
            if (route6) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Support only one IPv6 default gateway"));
                return -1;
            }

            route6 = net->guestIP.routes[i];

            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported address family %d "
                             "Only IPv4 or IPv6 default gateway"),
                           VIR_SOCKET_ADDR_FAMILY(gateway));

            return -1;
        }
    }

    if (route4 &&
        !(gw4 = virSocketAddrFormat(virNetDevIPRouteGetGateway(route4))))
        goto cleanup;

    pret = PrlVmDevNet_SetDefaultGateway(sdknet, gw4 ? : "");
    prlsdkCheckRetGoto(pret, cleanup);

    if (route6 &&
        !(gw6 = virSocketAddrFormat(virNetDevIPRouteGetGateway(route6))))
        goto cleanup;

    pret = PrlVmDevNet_SetDefaultGatewayIPv6(sdknet, gw6 ? : "");
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;

 cleanup:
    VIR_FREE(gw4);
    VIR_FREE(gw6);

    return ret;
}

static int prlsdkConfigureNet(vzDriverPtr driver ATTRIBUTE_UNUSED,
                              virDomainObjPtr dom ATTRIBUTE_UNUSED,
                              PRL_HANDLE sdkdom,
                              virDomainNetDefPtr net,
                              bool isCt, bool create)
{
    PRL_RESULT pret;
    PRL_HANDLE sdknet = PRL_INVALID_HANDLE;
    PRL_HANDLE addrlist = PRL_INVALID_HANDLE;
    size_t i;
    int ret = -1;
    char macstr[PRL_MAC_STRING_BUFNAME];
    char *addrstr = NULL;
    bool ipv6present = false;
    bool ipv4present = false;

    if (prlsdkCheckNetUnsupportedParams(net) < 0)
        return -1;

    if (create) {
        pret = PrlVmCfg_CreateVmDev(sdkdom, PDE_GENERIC_NETWORK_ADAPTER, &sdknet);
        prlsdkCheckRetGoto(pret, cleanup);
    } else {
        sdknet = prlsdkFindNetByMAC(sdkdom, &net->mac);
        if (sdknet == PRL_INVALID_HANDLE)
            return -1;
    }

    pret = PrlVmDev_SetEnabled(sdknet, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetConnected(sdknet, net->linkstate !=
                                 VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN);

    prlsdkCheckRetGoto(pret, cleanup);

    if (net->ifname) {
        pret = PrlVmDevNet_SetHostInterfaceName(sdknet, net->ifname);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    prlsdkFormatMac(&net->mac, macstr);
    pret = PrlVmDevNet_SetMacAddress(sdknet, macstr);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlApi_CreateStringsList(&addrlist);
    prlsdkCheckRetGoto(pret, cleanup);

    for (i = 0; i < net->guestIP.nips; i++) {
        char *tmpstr;

        if (AF_INET == VIR_SOCKET_ADDR_FAMILY(&net->guestIP.ips[i]->address))
            ipv4present = true;
        else if (AF_INET6 == VIR_SOCKET_ADDR_FAMILY(&net->guestIP.ips[i]->address))
            ipv6present = true;
        else
            continue;

        if (!(tmpstr = virSocketAddrFormat(&net->guestIP.ips[i]->address)))
            goto cleanup;

        if (virAsprintf(&addrstr, "%s/%d", tmpstr, net->guestIP.ips[i]->prefix) < 0) {
            VIR_FREE(tmpstr);
            goto cleanup;
        }

        VIR_FREE(tmpstr);
        pret = PrlStrList_AddItem(addrlist, addrstr);
        prlsdkCheckRetGoto(pret, cleanup);

        VIR_FREE(addrstr);
    }

    if (ipv4present || ipv6present) {
        pret = PrlVmDevNet_SetNetAddresses(sdknet, addrlist);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    pret = PrlVmDevNet_SetConfigureWithDhcp(sdknet, !ipv4present);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDevNet_SetConfigureWithDhcpIPv6(sdknet, !ipv6present);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDevNet_SetAutoApply(sdknet, true);
    prlsdkCheckRetGoto(pret, cleanup);

    if (prlsdkConfigureGateways(sdknet, net))
        goto cleanup;

    if (isCt) {
        if (net->model)
            VIR_WARN("Setting network adapter for containers is not "
                     "supported by vz driver.");
    } else {
        if (STREQ(net->model, "rtl8139")) {
            pret = PrlVmDevNet_SetAdapterType(sdknet, PNT_RTL);
        } else if (STREQ(net->model, "e1000")) {
            pret = PrlVmDevNet_SetAdapterType(sdknet, PNT_E1000);
        } else if (STREQ(net->model, "virtio")) {
            pret = PrlVmDevNet_SetAdapterType(sdknet, PNT_VIRTIO);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Specified network adapter model is not "
                             "supported by vz driver."));
            goto cleanup;
        }
        prlsdkCheckRetGoto(pret, cleanup);
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (STREQ(net->data.network.name, PARALLELS_DOMAIN_ROUTED_NETWORK_NAME)) {
            pret = PrlVmDev_SetEmulatedType(sdknet, PNA_ROUTED);
            prlsdkCheckRetGoto(pret, cleanup);
        } else {
            pret = PrlVmDev_SetEmulatedType(sdknet, PNA_BRIDGED_NETWORK);
            prlsdkCheckRetGoto(pret, cleanup);

            pret = PrlVmDevNet_SetVirtualNetworkId(sdknet, net->data.network.name);
            prlsdkCheckRetGoto(pret, cleanup);
        }

    } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {

        pret = PrlVmDev_SetEmulatedType(sdknet, PNA_BRIDGE);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlVmDevNet_SetVirtualNetworkId(sdknet, net->data.bridge.brname);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    pret = PrlVmDevNet_SetPktFilterPreventMacSpoof(sdknet,
                net->trustGuestRxFilters == VIR_TRISTATE_BOOL_YES);
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;
 cleanup:
    VIR_FREE(addrstr);
    PrlHandle_Free(addrlist);
    PrlHandle_Free(sdknet);
    return ret;
}

static PRL_HANDLE
prlsdkFindNetByMAC(PRL_HANDLE sdkdom, virMacAddrPtr mac)
{
    PRL_RESULT pret;
    PRL_UINT32 adaptersCount;
    PRL_UINT32 i;
    PRL_HANDLE adapter = PRL_INVALID_HANDLE;
    char adapterMac[PRL_MAC_STRING_BUFNAME];
    char expectedMac[PRL_MAC_STRING_BUFNAME];
    char virMac[VIR_MAC_STRING_BUFLEN];

    prlsdkFormatMac(mac, expectedMac);

    pret = PrlVmCfg_GetNetAdaptersCount(sdkdom, &adaptersCount);
    prlsdkCheckRetGoto(pret, cleanup);

    for (i = 0; i < adaptersCount; ++i) {
        pret = PrlVmCfg_GetNetAdapter(sdkdom, i, &adapter);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = prlsdkGetStringParamBuf(PrlVmDevNet_GetMacAddress,
                                       adapter, adapterMac, sizeof(adapterMac));
        prlsdkCheckRetGoto(pret, cleanup);

        if (STREQ(adapterMac, expectedMac))
            return adapter;

        PrlHandle_Free(adapter);
        adapter = PRL_INVALID_HANDLE;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("No net with mac '%s'"), virMacAddrFormat(mac, virMac));

 cleanup:
    PrlHandle_Free(adapter);
    return adapter;
}

static int prlsdkConfigureDisk(vzDriverPtr driver,
                               PRL_HANDLE sdkdom,
                               virDomainDiskDefPtr disk,
                               bool create)
{
    PRL_RESULT pret;
    PRL_HANDLE sdkdisk = PRL_INVALID_HANDLE;
    int ret = -1;
    PRL_VM_DEV_EMULATION_TYPE emutype;
    PRL_MASS_STORAGE_INTERFACE_TYPE sdkbus;
    int idx;
    virDomainDeviceDriveAddressPtr drive;
    PRL_DEVICE_TYPE devType;
    PRL_CLUSTERED_DEVICE_SUBTYPE scsiModel;
    const char *path = disk->src->path ? : "";

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
        devType = PDE_HARD_DISK;
    else
        devType = PDE_OPTICAL_DISK;

    if (create) {
        pret = PrlVmCfg_CreateVmDev(sdkdom, devType, &sdkdisk);
        prlsdkCheckRetGoto(pret, cleanup);
    } else {
        sdkdisk = prlsdkGetDisk(sdkdom, disk);
        if (sdkdisk == PRL_INVALID_HANDLE)
            return -1;
    }

    pret = PrlVmDev_SetEnabled(sdkdisk, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetConnected(sdkdisk, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    if (disk->src->type == VIR_STORAGE_TYPE_FILE)
        emutype = PDT_USE_IMAGE_FILE;
    else
        emutype = PDT_USE_REAL_DEVICE;

    pret = PrlVmDev_SetEmulatedType(sdkdisk, emutype);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetSysName(sdkdisk, path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetFriendlyName(sdkdisk, path);
    prlsdkCheckRetGoto(pret, cleanup);

    drive = &disk->info.addr.drive;

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        sdkbus = PMS_IDE_DEVICE;
        idx = 2 * drive->bus + drive->unit;
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        sdkbus = PMS_SCSI_DEVICE;
        idx = drive->unit;
        break;
    case VIR_DOMAIN_DISK_BUS_SATA:
        sdkbus = PMS_SATA_DEVICE;
        idx = drive->unit;
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified disk bus is not "
                         "supported by vz driver."));
        goto cleanup;
    }

    if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        if (vzGetDefaultSCSIModel(driver, &scsiModel) < 0)
            goto cleanup;
        pret = PrlVmDev_SetSubType(sdkdisk, scsiModel);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    pret = PrlVmDev_SetIfaceType(sdkdisk, sdkbus);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetStackIndex(sdkdisk, idx);
    prlsdkCheckRetGoto(pret, cleanup);

    if (devType == PDE_HARD_DISK) {
        pret = PrlVmDevHd_SetSerialNumber(sdkdisk, disk->serial);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    return 0;
 cleanup:
    PrlHandle_Free(sdkdisk);
    return ret;
}

static PRL_HANDLE
prlsdkGetDisk(PRL_HANDLE sdkdom, virDomainDiskDefPtr disk)
{
    PRL_RESULT pret;
    PRL_UINT32 num;
    size_t i;
    PRL_HANDLE sdkdisk = PRL_INVALID_HANDLE;
    int bus;
    char *dst = NULL;
    PRL_DEVICE_TYPE devType;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
        devType = PDE_HARD_DISK;
    else
        devType = PDE_OPTICAL_DISK;

    pret = PrlVmCfg_GetDevsCountByType(sdkdom, devType, &num);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < num; ++i) {
        pret = PrlVmCfg_GetDevByType(sdkdom, devType, i, &sdkdisk);
        prlsdkCheckRetGoto(pret, error);

        if (prlsdkGetDiskId(sdkdisk, &bus, &dst) < 0)
            goto error;

        if (disk->bus == bus && STREQ(disk->dst, dst)) {
            VIR_FREE(dst);
            return sdkdisk;
        }

        PrlHandle_Free(sdkdisk);
        sdkdisk = PRL_INVALID_HANDLE;
        VIR_FREE(dst);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("No disk with bus '%s' and target '%s'"),
                   virDomainDiskBusTypeToString(disk->bus), disk->dst);
    return PRL_INVALID_HANDLE;

 error:
    VIR_FREE(dst);
    PrlHandle_Free(sdkdisk);
    return PRL_INVALID_HANDLE;
}

int
prlsdkAttachDevice(vzDriverPtr driver,
                   virDomainObjPtr dom,
                   virDomainDeviceDefPtr dev)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (prlsdkConfigureDisk(driver, privdom->sdkdom,
                                dev->data.disk, true) < 0)
            return -1;

        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (!IS_CT(dom->def)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("attaching network device to VM is unsupported"));
            return -1;
        }

        if (prlsdkConfigureNet(driver, dom, privdom->sdkdom, dev->data.net,
                               IS_CT(dom->def), true) < 0)
            return -1;

        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if (dom->def->ngraphics > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("domain already has VNC graphics"));
            return -1;
        }

        if (prlsdkApplyGraphicsParams(privdom->sdkdom, dev->data.graphics) < 0)
            return -1;

        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("attaching device type '%s' is unsupported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    job = PrlVm_CommitEx(privdom->sdkdom, PVCF_DETACH_HDD_BUNDLE);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

int
prlsdkDetachDevice(vzDriverPtr driver ATTRIBUTE_UNUSED,
                   virDomainObjPtr dom,
                   virDomainDeviceDefPtr dev)
{
    int ret = -1;
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE sdkdev = PRL_INVALID_HANDLE;
    PRL_RESULT pret;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        sdkdev = prlsdkGetDisk(privdom->sdkdom, dev->data.disk);
        if (sdkdev == PRL_INVALID_HANDLE)
            goto cleanup;

        pret = PrlVmDev_Remove(sdkdev);
        prlsdkCheckRetGoto(pret, cleanup);

        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (!IS_CT(dom->def)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("detaching network device from VM is unsupported"));
            goto cleanup;
        }

        sdkdev = prlsdkFindNetByMAC(privdom->sdkdom, &dev->data.net->mac);
        if (sdkdev == PRL_INVALID_HANDLE)
            goto cleanup;

        pret = PrlVmDev_Remove(sdkdev);
        prlsdkCheckRetGoto(pret, cleanup);

        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if (dom->def->ngraphics < 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot find VNC graphics device"));
            goto cleanup;
        }

        if (prlsdkApplyGraphicsParams(privdom->sdkdom, NULL) < 0)
            goto cleanup;

        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("detaching device type '%s' is unsupported"),
                       virDomainDeviceTypeToString(dev->type));
        goto cleanup;
    }

    job = PrlVm_CommitEx(privdom->sdkdom, PVCF_DETACH_HDD_BUNDLE);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    ret = 0;

 cleanup:

    PrlHandle_Free(sdkdev);
    return ret;
}

int
prlsdkUpdateDevice(vzDriverPtr driver,
                   virDomainObjPtr dom,
                   virDomainDeviceDefPtr dev)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (prlsdkConfigureDisk(driver, privdom->sdkdom, dev->data.disk,
                                false) < 0)
            return -1;

        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (prlsdkConfigureNet(driver, dom, privdom->sdkdom, dev->data.net,
                               IS_CT(dom->def), false) < 0)
            return -1;

        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if (dom->def->ngraphics < 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot find VNC graphics device"));
            return -1;
        }

        if (prlsdkApplyGraphicsParams(privdom->sdkdom, dev->data.graphics) < 0)
            return -1;

        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("updating device type '%s' is unsupported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    job = PrlVm_CommitEx(privdom->sdkdom, PVCF_DETACH_HDD_BUNDLE);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

static int
prlsdkAddFS(PRL_HANDLE sdkdom, virDomainFSDefPtr fs)
{
    PRL_RESULT pret;
    PRL_HANDLE sdkdisk = PRL_INVALID_HANDLE;
    int ret = -1;
    char *storage = NULL;

    if (fs->type == VIR_DOMAIN_FS_TYPE_TEMPLATE)
        return 0;

    if (prlsdkCheckFSUnsupportedParams(fs) < 0)
        return -1;

    pret = PrlVmCfg_CreateVmDev(sdkdom, PDE_HARD_DISK, &sdkdisk);
    prlsdkCheckRetGoto(pret, cleanup);

    if (fs->type == VIR_DOMAIN_FS_TYPE_VOLUME) {
        if (virAsprintf(&storage, "libvirt://localhost/%s/%s", fs->src->srcpool->pool,
                        fs->src->srcpool->volume) < 0)
            goto cleanup;
        pret = PrlVmDevHd_SetStorageURL(sdkdisk, storage);
        prlsdkCheckRetGoto(pret, cleanup);
    }

    pret = PrlVmDev_SetEnabled(sdkdisk, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetConnected(sdkdisk, 1);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetEmulatedType(sdkdisk, PDT_USE_IMAGE_FILE);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetSysName(sdkdisk, fs->src->path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetImagePath(sdkdisk, fs->src->path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDev_SetFriendlyName(sdkdisk, fs->src->path);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmDevHd_SetMountPoint(sdkdisk, fs->dst);
    prlsdkCheckRetGoto(pret, cleanup);

    ret = 0;

 cleanup:
    VIR_FREE(storage);
    PrlHandle_Free(sdkdisk);
    return ret;
}

static int
prlsdkSetBootOrderCt(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    size_t i;
    PRL_HANDLE hdd = PRL_INVALID_HANDLE;
    PRL_RESULT pret;
    bool rootfs = false;
    int ret = -1;

    for (i = 0; i < def->nfss; i++) {

        pret = prlsdkAddDeviceToBootList(sdkdom, i, PDE_HARD_DISK, i + 1);
        prlsdkCheckRetExit(pret, -1);

        if (STREQ(def->fss[i]->dst, "/"))
            rootfs = true;
    }

    if (!rootfs) {
        /* if we have root mounted we don't need to explicitly set boot order */
        pret = PrlVmCfg_GetHardDisk(sdkdom, def->nfss, &hdd);
        prlsdkCheckRetExit(pret, -1);

        PrlVmDevHd_SetMountPoint(hdd, "/");
        prlsdkCheckRetGoto(pret, cleanup);
    }

    ret = 0;

 cleanup:
    PrlHandle_Free(hdd);
    return ret;
}

static int
prlsdkSetBootOrderVm(PRL_HANDLE sdkdom, virDomainDefPtr def)
{
    size_t i;
    int idx[VIR_DOMAIN_BOOT_LAST] = { 0 };
    int bootIndex = 0;
    PRL_RESULT pret;
    PRL_UINT32 num;
    int sdkType;
    virDomainBootOrder virType;

    for (i = 0; i < def->os.nBootDevs; ++i) {
        virType = def->os.bootDevs[i];

        switch (virType) {
        case VIR_DOMAIN_BOOT_CDROM:
            sdkType = PDE_OPTICAL_DISK;
            break;
        case VIR_DOMAIN_BOOT_DISK:
            sdkType = PDE_HARD_DISK;
            break;
        case VIR_DOMAIN_BOOT_NET:
            sdkType = PDE_GENERIC_NETWORK_ADAPTER;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported boot device type: '%s'"),
                           virDomainBootTypeToString(virType));
            return -1;
        }

        pret = PrlVmCfg_GetDevsCountByType(sdkdom, sdkType, &num);
        prlsdkCheckRetExit(pret, -1);

        pret = prlsdkAddDeviceToBootList(sdkdom, idx[virType]++, sdkType, bootIndex++);
        prlsdkCheckRetExit(pret, -1);
    }

    return 0;
}

int
prlsdkDomainSetUserPassword(virDomainObjPtr dom,
                            const char *user,
                            const char *password)
{
    int ret = -1;
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    job = PrlVm_SetUserPasswd(privdom->sdkdom,
                              user,
                              password,
                              0);

    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    job = PrlVm_CommitEx(privdom->sdkdom, 0);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}

static int
prlsdkDoApplyConfig(vzDriverPtr driver,
                    virDomainObjPtr dom,
                    PRL_HANDLE sdkdom,
                    virDomainDefPtr def)
{
    PRL_RESULT pret;
    size_t i;
    char uuidstr[VIR_UUID_STRING_BRACED_BUFLEN];
    char *mask = NULL;

    if (prlsdkCheckUnsupportedParams(sdkdom, def) < 0)
        return -1;

    if (def->description) {
        pret = PrlVmCfg_SetDescription(sdkdom, def->description);
        prlsdkCheckRetGoto(pret, error);
    }

    if (def->name) {
        pret = PrlVmCfg_SetName(sdkdom, def->name);
        prlsdkCheckRetGoto(pret, error);
    }

    if (def->uuid) {
        prlsdkUUIDFormat(def->uuid, uuidstr);

        pret = PrlVmCfg_SetUuid(sdkdom, uuidstr);
        prlsdkCheckRetGoto(pret, error);
    }

    pret = PrlVmCfg_SetRamSize(sdkdom, virDomainDefGetMemoryTotal(def) >> 10);
    prlsdkCheckRetGoto(pret, error);

    pret = PrlVmCfg_SetCpuCount(sdkdom, virDomainDefGetVcpus(def));
    prlsdkCheckRetGoto(pret, error);

    if (!(mask = virBitmapFormat(def->cpumask)))
        goto error;

    pret = PrlVmCfg_SetCpuMask(sdkdom, mask);
    prlsdkCheckRetGoto(pret, error);
    VIR_FREE(mask);

    switch (def->os.arch) {
    case VIR_ARCH_X86_64:
        pret = PrlVmCfg_SetCpuMode(sdkdom, PCM_CPU_MODE_64);
        break;
    case VIR_ARCH_I686:
        pret = PrlVmCfg_SetCpuMode(sdkdom, PCM_CPU_MODE_32);
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU mode: %s"),
                       virArchToString(def->os.arch));
        goto error;
    }
    prlsdkCheckRetGoto(pret, error);

    if (prlsdkClearDevices(sdkdom) < 0)
        goto error;

    if (prlsdkRemoveBootDevices(sdkdom) < 0)
        goto error;

    for (i = 0; i < def->nnets; i++) {
        if (prlsdkConfigureNet(driver, dom, sdkdom, def->nets[i],
                               IS_CT(def), true) < 0)
            goto error;
    }

    if (def->ngraphics > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver supports only VNC graphics"));
        goto error;
    }

    if (prlsdkApplyGraphicsParams(sdkdom,
                                  def->ngraphics == 1 ? def->graphics[0] : NULL) < 0)
        goto error;

    if (prlsdkApplyVideoParams(sdkdom, def) < 0)
        goto error;

    for (i = 0; i < def->nserials; i++) {
        if (prlsdkAddSerial(sdkdom, def->serials[i]) < 0)
            goto error;
    }

    /* It is important that we add filesystems first and then disks as we rely
     * on this information in prlsdkSetBootOrderCt */
    for (i = 0; i < def->nfss; i++) {
        if (prlsdkAddFS(sdkdom, def->fss[i]) < 0)
            goto error;
    }

    /* filesystems first, disks go after them as we rely on this order in
     * prlsdkSetBootOrderCt */
    for (i = 0; i < def->ndisks; i++) {
        if (prlsdkConfigureDisk(driver, sdkdom, def->disks[i],
                                true) < 0)
            goto error;
    }

    if (IS_CT(def)) {
        if (prlsdkSetBootOrderCt(sdkdom, def) < 0)
            goto error;
    } else {
        if (prlsdkSetBootOrderVm(sdkdom, def) < 0)
            goto error;
    }

    return 0;

 error:
    VIR_FREE(mask);

    return -1;
}

int
prlsdkApplyConfig(vzDriverPtr driver,
                  virDomainObjPtr dom,
                  virDomainDefPtr new)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    int ret;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    ret = prlsdkDoApplyConfig(driver, dom, privdom->sdkdom, new);

    if (ret == 0) {
        job = PrlVm_CommitEx(privdom->sdkdom, PVCF_DETACH_HDD_BUNDLE);
        if (PRL_FAILED(waitDomainJob(job, dom)))
            ret = -1;
    }

    return ret;
}

int
prlsdkCreateVm(vzDriverPtr driver, virDomainDefPtr def)
{
    PRL_HANDLE sdkdom = PRL_INVALID_HANDLE;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_HANDLE srvconf = PRL_INVALID_HANDLE;
    PRL_RESULT pret;
    int ret = -1;

    pret = PrlSrv_CreateVm(driver->server, &sdkdom);
    prlsdkCheckRetGoto(pret, cleanup);

    job = PrlSrv_GetSrvConfig(driver->server);
    if (PRL_FAILED(getJobResult(job, &result)))
        goto cleanup;

    pret = PrlResult_GetParamByIndex(result, 0, &srvconf);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmCfg_SetDefaultConfig(sdkdom, srvconf, PVS_GUEST_VER_LIN_REDHAT, 0);
    prlsdkCheckRetGoto(pret, cleanup);

    pret = PrlVmCfg_SetOfflineManagementEnabled(sdkdom, 0);
    prlsdkCheckRetGoto(pret, cleanup);

    if (prlsdkDoApplyConfig(driver, NULL, sdkdom, def) < 0)
        goto cleanup;

    job = PrlVm_Reg(sdkdom, "", 1);
    if (PRL_FAILED(waitJob(job)))
        goto cleanup;

    ret = 0;

 cleanup:
    PrlHandle_Free(sdkdom);
    PrlHandle_Free(srvconf);
    PrlHandle_Free(result);

    return ret;
}

static int
virStorageTranslatePoolLocal(virConnectPtr conn, virStorageSourcePtr src)
{

    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    virStorageVolInfo info;
    int ret = -1;

    if (!(pool = virStoragePoolLookupByName(conn, src->srcpool->pool)))
        return -1;
    if (virStoragePoolIsActive(pool) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("storage pool '%s' containing volume '%s' "
                         "is not active"), src->srcpool->pool,
                       src->srcpool->volume);
        goto cleanup;
    }

    if (!(vol = virStorageVolLookupByName(pool, src->srcpool->volume)))
        goto cleanup;

    if (virStorageVolGetInfo(vol, &info) < 0)
        goto cleanup;

    if (info.type != VIR_STORAGE_VOL_PLOOP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported volume format '%s'"),
                       virStorageVolTypeToString(info.type));
        goto cleanup;
    }

    if (!(src->path = virStorageVolGetPath(vol)))
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(pool);
    virObjectUnref(vol);
    return ret;
}


int
prlsdkCreateCt(virConnectPtr conn, virDomainDefPtr def)
{
    PRL_HANDLE sdkdom = PRL_INVALID_HANDLE;
    PRL_GET_VM_CONFIG_PARAM_DATA confParam;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    PRL_RESULT pret;
    PRL_UINT32 flags;
    vzConnPtr privconn = conn->privateData;
    vzDriverPtr driver = privconn->driver;
    int ret = -1;
    int useTemplate = 0;
    size_t i;

    for (i = 0; i < def->nfss; i++) {
        if (useTemplate) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Unsupported configuration"));
            return -1;
        }
        if (def->fss[i]->type == VIR_DOMAIN_FS_TYPE_TEMPLATE)
            useTemplate = 1;
        if (def->fss[i]->type == VIR_DOMAIN_FS_TYPE_VOLUME) {
            if (virStorageTranslatePoolLocal(conn, def->fss[i]->src) < 0)
                goto cleanup;
        }

    }

    if (useTemplate && def->nfss > 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Unsupported configuration"));
        return -1;
    }

    confParam.nVmType = PVT_CT;
    confParam.sConfigSample = "vswap.1024MB";
    confParam.nOsVersion = 0;

    job = PrlSrv_GetDefaultVmConfig(driver->server, &confParam, 0);
    if (PRL_FAILED(getJobResult(job, &result)))
        goto cleanup;

    pret = PrlResult_GetParamByIndex(result, 0, &sdkdom);
    prlsdkCheckRetGoto(pret, cleanup);

    if (useTemplate) {
        pret = PrlVmCfg_SetOsTemplate(sdkdom, def->fss[0]->src->path);
        prlsdkCheckRetGoto(pret, cleanup);

    }

    if (prlsdkDoApplyConfig(driver, NULL, sdkdom, def) < 0)
        goto cleanup;

    flags = PACF_NON_INTERACTIVE_MODE;
    if (!useTemplate)
        flags |= PRNVM_PRESERVE_DISK;
    job = PrlVm_RegEx(sdkdom, "", flags);
    if (PRL_FAILED(waitJob(job)))
        goto cleanup;

    ret = 0;

 cleanup:
    PrlHandle_Free(sdkdom);
    PrlHandle_Free(result);
    return ret;
}

/**
 * prlsdkDetachDomainHardDisks:
 *
 * @sdkdom: domain handle
 *
 * Returns 0 if hard disks were successfully detached or not detected.
 */
static int
prlsdkDetachDomainHardDisks(virDomainObjPtr dom)
{
    int ret = -1;
    PRL_RESULT pret;
    PRL_UINT32 hddCount;
    PRL_UINT32 i;
    PRL_HANDLE job;
    PRL_HANDLE sdkdisk = PRL_INVALID_HANDLE;
    vzDomObjPtr pdom = dom->privateData;
    PRL_HANDLE sdkdom = pdom->sdkdom;

    job = PrlVm_BeginEdit(sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    pret = PrlVmCfg_GetHardDisksCount(sdkdom, &hddCount);
    prlsdkCheckRetGoto(pret, cleanup);

    for (i = 0; i < hddCount; ++i) {
        pret = PrlVmCfg_GetHardDisk(sdkdom, 0, &sdkdisk);
        prlsdkCheckRetGoto(pret, cleanup);

        pret = PrlVmDev_Remove(sdkdisk);
        prlsdkCheckRetGoto(pret, cleanup);

        PrlHandle_Free(sdkdisk);
        sdkdisk = PRL_INVALID_HANDLE;
    }

    job = PrlVm_CommitEx(sdkdom, PVCF_DETACH_HDD_BUNDLE);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    ret = 0;

 cleanup:
    PrlHandle_Free(sdkdisk);
    return ret;
}

int
prlsdkUnregisterDomain(vzDriverPtr driver, virDomainObjPtr dom, unsigned int flags)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;
    virDomainSnapshotObjListPtr snapshots = NULL;
    VIRTUAL_MACHINE_STATE domainState;
    int ret = -1;
    int num;

    if (prlsdkGetDomainState(dom, privdom->sdkdom, &domainState) < 0)
        return -1;

    if (VMS_SUSPENDED == domainState &&
        !(flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE)) {

        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Refusing to undefine while domain managed "
                         "save image exists"));
        return -1;
    }

    if (!(snapshots = prlsdkLoadSnapshots(dom)))
        return -1;

    if ((num = virDomainSnapshotObjListNum(snapshots, NULL, 0)) < 0)
        goto cleanup;

    if (num > 0 && !(flags & VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Refusing to undefine while snapshots exist"));
        goto cleanup;
    }

    if (prlsdkDetachDomainHardDisks(dom))
        goto cleanup;

    job = PrlVm_Delete(privdom->sdkdom, PRL_INVALID_HANDLE);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    prlsdkSendEvent(driver, dom, VIR_DOMAIN_EVENT_UNDEFINED,
                    VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    virDomainObjListRemove(driver->domains, dom);
    virObjectLock(dom);

    ret = 0;
 cleanup:

    virDomainSnapshotObjListFree(snapshots);
    return ret;
}

int
prlsdkDomainManagedSaveRemove(virDomainObjPtr dom)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;

    job = PrlVm_DropSuspendedState(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

static int
prlsdkExtractStatsParam(PRL_HANDLE sdkstats, const char *name, long long *val)
{
    PRL_HANDLE param = PRL_INVALID_HANDLE;
    PRL_RESULT pret;
    PRL_INT64 pval = 0;
    int ret = -1;

    pret = PrlEvent_GetParamByName(sdkstats, name, &param);
    if (pret == PRL_ERR_NO_DATA) {
        *val = -1;
        ret = 0;
        goto cleanup;
    } else if (PRL_FAILED(pret)) {
        logPrlError(pret);
        goto cleanup;
    }
    pret = PrlEvtPrm_ToInt64(param, &pval);
    prlsdkCheckRetGoto(pret, cleanup);

    *val = pval;
    ret = 0;

 cleanup:
    PrlHandle_Free(param);
    return ret;
}

#define PARALLELS_STATISTICS_TIMEOUT (60 * 1000)

int
prlsdkGetBlockStats(PRL_HANDLE sdkstats,
                    virDomainDiskDefPtr disk,
                    virDomainBlockStatsPtr stats,
                    bool isCt)
{
    virDomainDeviceDriveAddressPtr address;
    int idx;
    const char *prefix;
    int ret = -1;
    char *name = NULL;

    address = &disk->info.addr.drive;

    if (isCt) {
        prefix = "hdd";
        idx = address->unit;
    } else {
        switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            prefix = "ide";
            idx = address->bus * 2 + address->unit;
            break;
        case VIR_DOMAIN_DISK_BUS_SATA:
            prefix = "sata";
            idx = address->unit;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            prefix = "scsi";
            idx = address->unit;
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown disk bus: %X"), disk->bus);
            goto cleanup;
        }
    }


#define PRLSDK_GET_STAT_PARAM(VAL, TYPE, NAME)                          \
    if (virAsprintf(&name, "devices.%s%d.%s", prefix, idx, NAME) < 0)   \
        goto cleanup;                                                   \
    if (prlsdkExtractStatsParam(sdkstats, name, &stats->VAL) < 0)       \
        goto cleanup;                                                   \
    VIR_FREE(name);

    PARALLELS_BLOCK_STATS_FOREACH(PRLSDK_GET_STAT_PARAM)

#undef PRLSDK_GET_STAT_PARAM

    ret = 0;

 cleanup:

    VIR_FREE(name);
    return ret;
}


static PRL_HANDLE
prlsdkFindNetByPath(PRL_HANDLE sdkdom, const char *path)
{
    PRL_UINT32 count = 0;
    PRL_RESULT pret;
    size_t i;
    char *name = NULL;
    PRL_HANDLE net = PRL_INVALID_HANDLE;

    pret = PrlVmCfg_GetNetAdaptersCount(sdkdom, &count);
    prlsdkCheckRetGoto(pret, error);

    for (i = 0; i < count; ++i) {
        pret = PrlVmCfg_GetNetAdapter(sdkdom, i, &net);
        prlsdkCheckRetGoto(pret, error);

        if (!(name = prlsdkGetStringParamVar(PrlVmDevNet_GetHostInterfaceName,
                                             net)))
            goto error;

        if (STREQ(name, path))
            break;

        VIR_FREE(name);
        PrlHandle_Free(net);
        net = PRL_INVALID_HANDLE;
    }

    if (net == PRL_INVALID_HANDLE)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path, '%s' is not a known interface"), path);
    return net;

 error:
    VIR_FREE(name);
    PrlHandle_Free(net);
    return PRL_INVALID_HANDLE;
}

int
prlsdkGetNetStats(PRL_HANDLE sdkstats, PRL_HANDLE sdkdom, const char *path,
                  virDomainInterfaceStatsPtr stats)
{
    int ret = -1;
    PRL_UINT32 net_index = -1;
    char *name = NULL;
    PRL_RESULT pret;
    PRL_HANDLE net = PRL_INVALID_HANDLE;

    net = prlsdkFindNetByPath(sdkdom, path);
    if (net == PRL_INVALID_HANDLE)
       goto cleanup;

    pret = PrlVmDev_GetIndex(net, &net_index);
    prlsdkCheckRetGoto(pret, cleanup);

#define PRLSDK_GET_NET_COUNTER(VAL, NAME)                           \
    if (virAsprintf(&name, "net.nic%u.%s", net_index, NAME) < 0)    \
        goto cleanup;                                               \
    if (prlsdkExtractStatsParam(sdkstats, name, &stats->VAL) < 0)   \
        goto cleanup;                                               \
    VIR_FREE(name);

    PRLSDK_GET_NET_COUNTER(rx_bytes, "bytes_in")
    PRLSDK_GET_NET_COUNTER(rx_packets, "pkts_in")
    PRLSDK_GET_NET_COUNTER(tx_bytes, "bytes_out")
    PRLSDK_GET_NET_COUNTER(tx_packets, "pkts_out")
    stats->rx_errs = -1;
    stats->rx_drop = -1;
    stats->tx_errs = -1;
    stats->tx_drop = -1;

#undef PRLSDK_GET_NET_COUNTER
    ret = 0;

 cleanup:
    VIR_FREE(name);
    PrlHandle_Free(net);

    return ret;
}

int
prlsdkGetVcpuStats(PRL_HANDLE sdkstats, int idx, unsigned long long *vtime)
{
    char *name = NULL;
    long long ptime = 0;
    int ret = -1;

    if (virAsprintf(&name, "guest.vcpu%u.time", (unsigned int)idx) < 0)
        goto cleanup;
    if (prlsdkExtractStatsParam(sdkstats, name, &ptime) < 0)
        goto cleanup;
    *vtime = ptime == -1 ? 0 : ptime;
    ret = 0;

 cleanup:
    VIR_FREE(name);
    return ret;
}

int
prlsdkGetMemoryStats(PRL_HANDLE sdkstats,
                     virDomainMemoryStatPtr stats,
                     unsigned int nr_stats)
{
    int ret = -1;
    long long v = 0, t = 0, u = 0;
    size_t i = 0;

#define PRLSDK_GET_COUNTER(NAME, VALUE)                             \
    if (prlsdkExtractStatsParam(sdkstats, NAME, &VALUE) < 0)        \
        goto cleanup;                                               \

#define PRLSDK_MEMORY_STAT_SET(TAG, VALUE)                          \
    if (i < nr_stats) {                                             \
        stats[i].tag = (TAG);                                       \
        stats[i].val = (VALUE);                                     \
        i++;                                                        \
    }

    i = 0;

    // count to kb
    PRLSDK_GET_COUNTER("guest.ram.swap_in", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_SWAP_IN, v << 12)

    PRLSDK_GET_COUNTER("guest.ram.swap_out", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_SWAP_OUT, v << 12)

    PRLSDK_GET_COUNTER("guest.ram.minor_fault", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT, v)

    PRLSDK_GET_COUNTER("guest.ram.major_fault", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT, v)

    PRLSDK_GET_COUNTER("guest.ram.total", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_AVAILABLE, v << 10)

    PRLSDK_GET_COUNTER("guest.ram.balloon_actual", v)
    if (v != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON, v << 10)

    PRLSDK_GET_COUNTER("guest.ram.usage", u)
    PRLSDK_GET_COUNTER("guest.ram.total", t)
    if (u != -1 && t != -1)
        PRLSDK_MEMORY_STAT_SET(VIR_DOMAIN_MEMORY_STAT_UNUSED, (t - u) << 10)

#undef PRLSDK_GET_COUNTER
#undef PRLSDK_MEMORY_STAT_SET

    ret = i;
 cleanup:

    return ret;
}

/* memsize is in MiB */
int prlsdkSetMemsize(virDomainObjPtr dom, unsigned int memsize)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;
    PRL_RESULT pret;

    job = PrlVm_BeginEdit(privdom->sdkdom);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto error;

    pret = PrlVmCfg_SetRamSize(privdom->sdkdom, memsize);
    prlsdkCheckRetGoto(pret, error);

    job = PrlVm_CommitEx(privdom->sdkdom, 0);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto error;

    return 0;

 error:
    return -1;
}

static long long
prlsdkParseDateTime(const char *str)
{
    struct tm tm;
    const char *tmp;

    tmp = strptime(str, "%Y-%m-%d %H:%M:%S", &tm);
    if (!tmp || *tmp != '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected DateTime format: '%s'"), str);
        return -1;
    }

    return mktime(&tm);
}

static virDomainSnapshotObjListPtr
prlsdkParseSnapshotTree(const char *treexml)
{
    virDomainSnapshotObjListPtr ret = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr root;
    xmlNodePtr *nodes = NULL;
    virDomainSnapshotDefPtr def = NULL;
    virDomainSnapshotObjPtr snapshot;
    virDomainSnapshotObjPtr current = NULL;
    virDomainSnapshotObjListPtr snapshots = NULL;
    char *xmlstr = NULL;
    int n;
    size_t i;

    if (!(snapshots = virDomainSnapshotObjListNew()))
        return NULL;

    if (*treexml == '\0')
        return snapshots;

    if (!(xml = virXMLParse(NULL, treexml, _("(snapshot_tree)"))))
        goto cleanup;

    root = xmlDocGetRootElement(xml);
    if (!xmlStrEqual(root->name, BAD_CAST "ParallelsSavedStates")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected root element: '%s'"), root->name);
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    ctxt->node = root;

    if ((n = virXPathNodeSet("//SavedStateItem", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract snapshot nodes"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        if (nodes[i]->parent == root)
            continue;

        if (VIR_ALLOC(def) < 0)
            goto cleanup;

        ctxt->node = nodes[i];

        def->name = virXPathString("string(./@guid)", ctxt);
        if (!def->name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing 'guid' attribute"));
            goto cleanup;
        }

        def->parent = virXPathString("string(../@guid)", ctxt);

        xmlstr = virXPathString("string(./DateTime)", ctxt);
        if (!xmlstr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing 'DateTime' element"));
            goto cleanup;
        }
        if ((def->creationTime = prlsdkParseDateTime(xmlstr)) < 0)
            goto cleanup;
        VIR_FREE(xmlstr);

        def->description = virXPathString("string(./Description)", ctxt);

        def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
        xmlstr = virXPathString("string(./@state)", ctxt);
        if (!xmlstr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing 'state' attribute"));
            goto cleanup;
        } else if (STREQ(xmlstr, "poweron")) {
            def->state = VIR_DOMAIN_RUNNING;
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
        } else if (STREQ(xmlstr, "pause")) {
            def->state = VIR_DOMAIN_PAUSED;
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
        } else if (STREQ(xmlstr, "suspend")) {
            def->state = VIR_DOMAIN_SHUTOFF;
        } else if (STREQ(xmlstr, "poweroff")) {
            def->state = VIR_DOMAIN_SHUTOFF;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected snapshot state: %s"), xmlstr);
        }
        VIR_FREE(xmlstr);

        xmlstr = virXPathString("string(./@current)", ctxt);
        def->current = xmlstr && STREQ("yes", xmlstr);
        VIR_FREE(xmlstr);

        if (!(snapshot = virDomainSnapshotAssignDef(snapshots, def)))
            goto cleanup;
        def = NULL;

        if (snapshot->def->current) {
            if (current) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("too many current snapshots"));
                goto cleanup;
            }
            current = snapshot;
        }
    }

    if (virDomainSnapshotUpdateRelations(snapshots) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("snapshots have inconsistent relations"));
        goto cleanup;
    }

    ret = snapshots;
    snapshots = NULL;

 cleanup:
    virDomainSnapshotObjListFree(snapshots);
    VIR_FREE(nodes);
    VIR_FREE(xmlstr);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(def);

    return ret;
}

virDomainSnapshotObjListPtr
prlsdkLoadSnapshots(virDomainObjPtr dom)
{
    virDomainSnapshotObjListPtr ret = NULL;
    PRL_HANDLE job;
    PRL_HANDLE result = PRL_INVALID_HANDLE;
    vzDomObjPtr privdom = dom->privateData;
    char *treexml = NULL;

    job = PrlVm_GetSnapshotsTreeEx(privdom->sdkdom, PGST_WITHOUT_SCREENSHOTS);
    if (PRL_FAILED(getDomainJobResult(job, dom, &result)))
        goto cleanup;

    if (!(treexml = prlsdkGetStringParamVar(PrlResult_GetParamAsString, result)))
        goto cleanup;

    ret = prlsdkParseSnapshotTree(treexml);
 cleanup:

    PrlHandle_Free(result);
    VIR_FREE(treexml);
    return ret;
}

int prlsdkCreateSnapshot(virDomainObjPtr dom, const char *description)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;

    job = PrlVm_CreateSnapshot(privdom->sdkdom, "",
                               description ? : "");
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

int prlsdkDeleteSnapshot(virDomainObjPtr dom, const char *uuid, bool children)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;

    job = PrlVm_DeleteSnapshot(privdom->sdkdom, uuid, children);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

int prlsdkSwitchToSnapshot(virDomainObjPtr dom, const char *uuid, bool paused)
{
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job;
    PRL_UINT32 flags = 0;

    if (paused)
        flags |= PSSF_SKIP_RESUME;

    job = PrlVm_SwitchToSnapshotEx(privdom->sdkdom, uuid, flags);
    if (PRL_FAILED(waitDomainJob(job, dom)))
        return -1;

    return 0;
}

/* high security is default choice for 2 reasons:
 * 1. as this is the highest set security we can't get
 * reject from server with high security settings
 * 2. this is on par with security level of driver
 * connection to dispatcher
 */

#define PRLSDK_MIGRATION_FLAGS (PSL_HIGH_SECURITY | PVMT_DONT_CREATE_DISK)

int prlsdkMigrate(virDomainObjPtr dom, virURIPtr uri,
                  const unsigned char *session_uuid,
                  const char *dname,
                  unsigned int flags)
{
    int ret = -1;
    vzDomObjPtr privdom = dom->privateData;
    PRL_HANDLE job = PRL_INVALID_HANDLE;
    char uuidstr[VIR_UUID_STRING_BRACED_BUFLEN];
    PRL_UINT32 vzflags = PRLSDK_MIGRATION_FLAGS;

    if (flags & VIR_MIGRATE_PAUSED)
        vzflags |= PVMT_DONT_RESUME_VM;

    prlsdkUUIDFormat(session_uuid, uuidstr);
    job = PrlVm_MigrateWithRenameEx(privdom->sdkdom, uri->server,
                                    uri->port, uuidstr,
                                    dname == NULL ? "" : dname,
                                    "",
                                    vzflags,
                                    0,
                                    PRL_TRUE
                                    );

    if (PRL_FAILED(waitDomainJob(job, dom)))
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}
