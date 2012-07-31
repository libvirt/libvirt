/*
 * parallels_driver.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include "datatypes.h"
#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "command.h"
#include "configmake.h"
#include "storage_file.h"
#include "storage_conf.h"
#include "nodeinfo.h"
#include "json.h"
#include "domain_conf.h"

#include "parallels_driver.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

#define PRLCTL                      "prlctl"
#define PARALLELS_DEFAULT_ARCH      "x86_64"

struct _parallelsConn {
    virMutex lock;
    virDomainObjList domains;
    virStoragePoolObjList pools;
    virCapsPtr caps;
};

typedef struct _parallelsConn parallelsConn;
typedef struct _parallelsConn *parallelsConnPtr;

static int parallelsClose(virConnectPtr conn);

static void
parallelsDriverLock(parallelsConnPtr driver)
{
    virMutexLock(&driver->lock);
}

static void
parallelsDriverUnlock(parallelsConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static int
parallelsDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}

static virCapsPtr
parallelsBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    struct utsname utsname;
    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine, 0, 0)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]) {
                                0x42, 0x1C, 0x00});

    if ((guest = virCapabilitiesAddGuest(caps, "hvm", PARALLELS_DEFAULT_ARCH,
                                         64, "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto no_memory;

    caps->defaultConsoleTargetType = parallelsDefaultConsoleType;
    return caps;

  no_memory:
    virReportOOMError();
    virCapabilitiesFree(caps);
    return NULL;
}

static char *
parallelsGetCapabilities(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    char *xml;

    parallelsDriverLock(privconn);
    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL)
        virReportOOMError();
    parallelsDriverUnlock(privconn);
    return xml;
}

static int
parallelsOpenDefault(virConnectPtr conn)
{
    parallelsConnPtr privconn;

    if (VIR_ALLOC(privconn) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        goto error;
    }

    if (!(privconn->caps = parallelsBuildCapabilities()))
        goto error;

    if (virDomainObjListInit(&privconn->domains) < 0)
        goto error;

    conn->privateData = privconn;

    return VIR_DRV_OPEN_SUCCESS;

  error:
    virDomainObjListDeinit(&privconn->domains);
    virCapabilitiesFree(privconn->caps);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
}

static virDrvOpenStatus
parallelsOpen(virConnectPtr conn,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              unsigned int flags)
{
    int ret;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "parallels"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* From this point on, the connection is for us. */
    if (
        conn->uri->path[0] == '\0' ||
        (conn->uri->path[0] == '/' && conn->uri->path[1] == '\0')) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("parallelsOpen: supply a path or use "
                         "parallels:///session"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STREQ(conn->uri->path, "/session"))
        ret = parallelsOpenDefault(conn);
    else
        return VIR_DRV_OPEN_DECLINED;

    if (ret != VIR_DRV_OPEN_SUCCESS)
        return ret;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
parallelsClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    virCapabilitiesFree(privconn->caps);
    virDomainObjListDeinit(&privconn->domains);
    conn->privateData = NULL;

    parallelsDriverUnlock(privconn);
    virMutexDestroy(&privconn->lock);

    VIR_FREE(privconn);
    return 0;
}

static int
parallelsGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *hvVer)
{
    /* TODO */
    *hvVer = 6;
    return 0;
}

static virDriver parallelsDriver = {
    .no = VIR_DRV_PARALLELS,
    .name = "Parallels",
    .open = parallelsOpen,            /* 0.10.0 */
    .close = parallelsClose,          /* 0.10.0 */
    .version = parallelsGetVersion,   /* 0.10.0 */
    .getHostname = virGetHostname,      /* 0.10.0 */
    .nodeGetInfo = nodeGetInfo,      /* 0.10.0 */
    .getCapabilities = parallelsGetCapabilities,      /* 0.10.0 */
};

/**
 * parallelsRegister:
 *
 * Registers the parallels driver
 */
int
parallelsRegister(void)
{
    char *prlctl_path;

    prlctl_path = virFindFileInPath(PRLCTL);
    if (!prlctl_path) {
        VIR_DEBUG("%s", _("Can't find prlctl command in the PATH env"));
        return 0;
    }

    VIR_FREE(prlctl_path);

    if (virRegisterDriver(&parallelsDriver) < 0)
        return -1;

    return 0;
}
