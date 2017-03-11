/*
 * bhyve_conf.c: bhyve config file
 *
 * Copyright (C) 2017 Roman Bogorodskiy
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

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "bhyve_conf.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_conf");

static virClassPtr virBhyveDriverConfigClass;
static void virBhyveDriverConfigDispose(void *obj);

static int virBhyveConfigOnceInit(void)
{
     if (!(virBhyveDriverConfigClass = virClassNew(virClassForObject(),
                                                   "virBhyveDriverConfig",
                                                   sizeof(virBhyveDriverConfig),
                                                   virBhyveDriverConfigDispose)))
         return -1;

     return 0;
}

VIR_ONCE_GLOBAL_INIT(virBhyveConfig)

virBhyveDriverConfigPtr
virBhyveDriverConfigNew(void)
{
    virBhyveDriverConfigPtr cfg;

    if (virBhyveConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virBhyveDriverConfigClass)))
        return NULL;

    if (VIR_STRDUP(cfg->firmwareDir, DATADIR "/uefi-firmware") < 0)
        goto error;

    return cfg;

 error:
    virObjectUnref(cfg);
    return NULL;
}

int
virBhyveLoadDriverConfig(virBhyveDriverConfigPtr cfg,
                         const char *filename)
{
    virConfPtr conf;
    int ret = -1;

    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read bhyve config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        return -1;

    if (virConfGetValueString(conf, "firmware_dir",
                              &cfg->firmwareDir) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virConfFree(conf);
    return ret;
}

virBhyveDriverConfigPtr
virBhyveDriverGetConfig(bhyveConnPtr driver)
{
    virBhyveDriverConfigPtr cfg;
    bhyveDriverLock(driver);
    cfg = virObjectRef(driver->config);
    bhyveDriverUnlock(driver);
    return cfg;
}

static void
virBhyveDriverConfigDispose(void *obj)
{
    virBhyveDriverConfigPtr cfg = obj;

    VIR_FREE(cfg->firmwareDir);
}
