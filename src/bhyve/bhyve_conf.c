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
#include "bhyve_domain.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_conf");

static virClass *virBhyveDriverConfigClass;
static void virBhyveDriverConfigDispose(void *obj);

static int virBhyveConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virBhyveDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virBhyveConfig);

struct _virBhyveDriverConfig *
virBhyveDriverConfigNew(void)
{
    struct _virBhyveDriverConfig *cfg;

    if (virBhyveConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virBhyveDriverConfigClass)))
        return NULL;

    cfg->firmwareDir = g_strdup(DATADIR "/uefi-firmware");

    return cfg;
}

int
virBhyveLoadDriverConfig(struct _virBhyveDriverConfig *cfg,
                         const char *filename)
{
    g_autoptr(virConf) conf = NULL;

    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read bhyve config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        return -1;

    if (virConfGetValueString(conf, "firmware_dir",
                              &cfg->firmwareDir) < 0)
        return -1;

    return 0;
}

struct _virBhyveDriverConfig *
virBhyveDriverGetConfig(struct _bhyveConn *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->config);
}

static void
virBhyveDriverConfigDispose(void *obj)
{
    struct _virBhyveDriverConfig *cfg = obj;

    g_free(cfg->firmwareDir);
}

void
bhyveDomainCmdlineDefFree(bhyveDomainCmdlineDef *def)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < def->num_args; i++)
        g_free(def->args[i]);

    g_free(def->args);
    g_free(def);
}
