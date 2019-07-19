/*
 * virsh-pool.c: Commands to manage storage pool
 *
 * Copyright (C) 2005, 2007-2016 Red Hat, Inc.
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
#include "virsh-pool.h"

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "conf/storage_conf.h"
#include "virstring.h"
#include "virtime.h"
#include "vsh-table.h"
#include "virenum.h"

#define VIRSH_COMMON_OPT_POOL_FULL(cflags) \
    VIRSH_COMMON_OPT_POOL(N_("pool name or uuid"), cflags)

#define VIRSH_COMMON_OPT_POOL_BUILD \
    {.name = "build", \
     .type = VSH_OT_BOOL, \
     .flags = 0, \
     .help = N_("build the pool as normal") \
    }

#define VIRSH_COMMON_OPT_POOL_NO_OVERWRITE \
    {.name = "no-overwrite", \
     .type = VSH_OT_BOOL, \
     .flags = 0, \
     .help = N_("do not overwrite any existing data") \
    }

#define VIRSH_COMMON_OPT_POOL_OVERWRITE \
    {.name = "overwrite", \
     .type = VSH_OT_BOOL, \
     .flags = 0, \
     .help = N_("overwrite any existing data") \
    }

#define VIRSH_COMMON_OPT_POOL_X_AS \
    {.name = "name", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = N_("name of the pool") \
    }, \
    {.name = "type", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = N_("type of the pool") \
    }, \
    {.name = "print-xml", \
     .type = VSH_OT_BOOL, \
     .help = N_("print XML document, but don't define/create") \
    }, \
    {.name = "source-host", \
     .type = VSH_OT_STRING, \
     .help = N_("source-host for underlying storage") \
    }, \
    {.name = "source-path", \
     .type = VSH_OT_STRING, \
     .help = N_("source path for underlying storage") \
    }, \
    {.name = "source-dev", \
     .type = VSH_OT_STRING, \
     .help = N_("source device for underlying storage") \
    }, \
    {.name = "source-name", \
     .type = VSH_OT_STRING, \
     .help = N_("source name for underlying storage") \
    }, \
    {.name = "target", \
     .type = VSH_OT_STRING, \
     .help = N_("target for underlying storage") \
    }, \
    {.name = "source-format", \
     .type = VSH_OT_STRING, \
     .help = N_("format for underlying storage") \
    }, \
    {.name = "auth-type", \
     .type = VSH_OT_STRING, \
     .help = N_("auth type to be used for underlying storage") \
    }, \
    {.name = "auth-username", \
     .type = VSH_OT_STRING, \
     .help = N_("auth username to be used for underlying storage") \
    }, \
    {.name = "secret-usage", \
     .type = VSH_OT_STRING, \
     .help = N_("auth secret usage to be used for underlying storage") \
    }, \
    {.name = "secret-uuid", \
     .type = VSH_OT_STRING, \
     .help = N_("auth secret UUID to be used for underlying storage") \
    }, \
    {.name = "adapter-name", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter name to be used for underlying storage") \
    }, \
    {.name = "adapter-wwnn", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter wwnn to be used for underlying storage") \
    }, \
    {.name = "adapter-wwpn", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter wwpn to be used for underlying storage") \
    }, \
    {.name = "adapter-parent", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter parent scsi_hostN to be used for underlying vHBA storage") \
    }, \
    {.name = "adapter-parent-wwnn", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter parent scsi_hostN wwnn to be used for underlying vHBA storage") \
    }, \
    {.name = "adapter-parent-wwpn", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter parent scsi_hostN wwpn to be used for underlying vHBA storage") \
    }, \
    {.name = "adapter-parent-fabric-wwn", \
     .type = VSH_OT_STRING, \
     .help = N_("adapter parent scsi_hostN fabric_wwn to be used for underlying vHBA storage") \
    }, \
    {.name = "source-protocol-ver", \
     .type = VSH_OT_STRING, \
     .help = N_("nfsvers value for NFS pool mount option") \
    }

virStoragePoolPtr
virshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd, const char *optname,
                      const char **name, unsigned int flags)
{
    virStoragePoolPtr pool = NULL;
    const char *n = NULL;
    virshControlPtr priv = ctl->privData;

    virCheckFlags(VIRSH_BYUUID | VIRSH_BYNAME, NULL);

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    if (cmd->skipChecks && !n)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flags & VIRSH_BYUUID) && strlen(n) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as pool UUID\n",
                 cmd->def->name, optname);
        pool = virStoragePoolLookupByUUIDString(priv->conn, n);
    }
    /* try it by NAME */
    if (!pool && (flags & VIRSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as pool NAME\n",
                 cmd->def->name, optname);
        pool = virStoragePoolLookupByName(priv->conn, n);
    }

    if (!pool)
        vshError(ctl, _("failed to get pool '%s'"), n);

    return pool;
}

/*
 * "pool-autostart" command
 */
static const vshCmdInfo info_pool_autostart[] = {
    {.name = "help",
     .data = N_("autostart a pool")
    },
    {.name = "desc",
     .data = N_("Configure a pool to be automatically started at boot.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_autostart[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT),

    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable autostarting")
    },
    {.name = NULL}
};

static bool
cmdPoolAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    int autostart;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virStoragePoolSetAutostart(pool, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark pool %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark pool %s as autostarted"), name);
        virStoragePoolFree(pool);
        return false;
    }

    if (autostart)
        vshPrintExtra(ctl, _("Pool %s marked as autostarted\n"), name);
    else
        vshPrintExtra(ctl, _("Pool %s unmarked as autostarted\n"), name);

    virStoragePoolFree(pool);
    return true;
}

/*
 * "pool-create" command
 */
static const vshCmdInfo info_pool_create[] = {
    {.name = "help",
     .data = N_("create a pool from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_create[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML pool description")),
    VIRSH_COMMON_OPT_POOL_BUILD,
    VIRSH_COMMON_OPT_POOL_NO_OVERWRITE,
    VIRSH_COMMON_OPT_POOL_OVERWRITE,

    {.name = NULL}
};

static bool
cmdPoolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *from = NULL;
    bool ret = true;
    char *buffer;
    bool build;
    bool overwrite;
    bool no_overwrite;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    build = vshCommandOptBool(cmd, "build");
    overwrite = vshCommandOptBool(cmd, "overwrite");
    no_overwrite = vshCommandOptBool(cmd, "no-overwrite");

    VSH_EXCLUSIVE_OPTIONS_EXPR("overwrite", overwrite,
                               "no-overwrite", no_overwrite);

    if (build)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD;
    if (overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE;
    if (no_overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    pool = virStoragePoolCreateXML(priv->conn, buffer, flags);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrintExtra(ctl, _("Pool %s created from %s\n"),
                      virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to create pool from %s"), from);
        ret = false;
    }
    return ret;
}

static const vshCmdOptDef opts_pool_define_as[] = {
    VIRSH_COMMON_OPT_POOL_X_AS,

    {.name = NULL}
};

static int
virshBuildPoolXML(vshControl *ctl,
                  const vshCmd *cmd,
                  const char **retname,
                  char **xml)
{
    const char *name = NULL, *type = NULL, *srcHost = NULL, *srcPath = NULL,
               *srcDev = NULL, *srcName = NULL, *srcFormat = NULL,
               *target = NULL, *authType = NULL, *authUsername = NULL,
               *secretUsage = NULL, *adapterName = NULL, *adapterParent = NULL,
               *adapterWwnn = NULL, *adapterWwpn = NULL, *secretUUID = NULL,
               *adapterParentWwnn = NULL, *adapterParentWwpn = NULL,
               *adapterParentFabricWwn = NULL, *protoVer = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    VSH_EXCLUSIVE_OPTIONS("secret-usage", "secret-uuid");

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        goto cleanup;
    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "source-host", &srcHost) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-path", &srcPath) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-dev", &srcDev) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-name", &srcName) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-format", &srcFormat) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "target", &target) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "auth-type", &authType) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "auth-username", &authUsername) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "secret-usage", &secretUsage) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "secret-uuid", &secretUUID) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-name", &adapterName) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-wwnn", &adapterWwnn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-wwpn", &adapterWwpn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-parent", &adapterParent) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-parent-wwnn", &adapterParentWwnn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-parent-wwpn", &adapterParentWwpn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "adapter-parent-fabric-wwn", &adapterParentFabricWwn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-protocol-ver", &protoVer) < 0)
        goto cleanup;

    virBufferAsprintf(&buf, "<pool type='%s'>\n", type);
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<name>%s</name>\n", name);
    if (srcHost || srcPath || srcDev || srcFormat || srcName ||
        (adapterWwnn && adapterWwpn) || adapterName) {
        virBufferAddLit(&buf, "<source>\n");
        virBufferAdjustIndent(&buf, 2);

        if (srcHost)
            virBufferAsprintf(&buf, "<host name='%s'/>\n", srcHost);
        if (srcPath)
            virBufferAsprintf(&buf, "<dir path='%s'/>\n", srcPath);
        if (srcDev)
            virBufferAsprintf(&buf, "<device path='%s'/>\n", srcDev);
        if (adapterWwnn && adapterWwpn) {
            virBufferAddLit(&buf, "<adapter type='fc_host'");
            if (adapterParent)
                virBufferAsprintf(&buf, " parent='%s'", adapterParent);
            else if (adapterParentWwnn && adapterParentWwpn)
                virBufferAsprintf(&buf, " parent_wwnn='%s' parent_wwpn='%s'",
                                  adapterParentWwnn, adapterParentWwpn);
            else if (adapterParentFabricWwn)
                virBufferAsprintf(&buf, " parent_fabric_wwn='%s'",
                                  adapterParentFabricWwn);
            virBufferAsprintf(&buf, " wwnn='%s' wwpn='%s'/>\n",
                              adapterWwnn, adapterWwpn);
        } else if (adapterName) {
            virBufferAsprintf(&buf, "<adapter type='scsi_host' name='%s'/>\n",
                              adapterName);
        }
        if (authType && authUsername && (secretUsage || secretUUID)) {
            virBufferAsprintf(&buf, "<auth type='%s' username='%s'>\n",
                              authType, authUsername);
            virBufferAdjustIndent(&buf, 2);
            if (secretUsage)
                virBufferAsprintf(&buf, "<secret usage='%s'/>\n", secretUsage);
            else
                virBufferAsprintf(&buf, "<secret uuid='%s'/>\n", secretUUID);
            virBufferAdjustIndent(&buf, -2);
            virBufferAddLit(&buf, "</auth>\n");
        }
        if (srcFormat)
            virBufferAsprintf(&buf, "<format type='%s'/>\n", srcFormat);
        if (srcName)
            virBufferAsprintf(&buf, "<name>%s</name>\n", srcName);

        if (protoVer)
            virBufferAsprintf(&buf, "<protocol ver='%s'/>\n", protoVer);

        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</source>\n");
    }
    if (target) {
        virBufferAddLit(&buf, "<target>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<path>%s</path>\n", target);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</target>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</pool>\n");

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }

    *xml = virBufferContentAndReset(&buf);
    *retname = name;
    return true;

 cleanup:
    virBufferFreeAndReset(&buf);
    return false;
}

/*
 * "pool-create-as" command
 */
static const vshCmdInfo info_pool_create_as[] = {
    {.name = "help",
     .data = N_("create a pool from a set of args")
    },
    {.name = "desc",
     .data = N_("Create a pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_create_as[] = {
    VIRSH_COMMON_OPT_POOL_X_AS,
    VIRSH_COMMON_OPT_POOL_BUILD,
    VIRSH_COMMON_OPT_POOL_NO_OVERWRITE,
    VIRSH_COMMON_OPT_POOL_OVERWRITE,

    {.name = NULL}
};

static bool
cmdPoolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    char *xml;
    bool printXML = vshCommandOptBool(cmd, "print-xml");
    bool build;
    bool overwrite;
    bool no_overwrite;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

    build = vshCommandOptBool(cmd, "build");
    overwrite = vshCommandOptBool(cmd, "overwrite");
    no_overwrite = vshCommandOptBool(cmd, "no-overwrite");

    VSH_EXCLUSIVE_OPTIONS_EXPR("overwrite", overwrite,
                               "no-overwrite", no_overwrite);

    if (build)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD;
    if (overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE;
    if (no_overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE;

    if (!virshBuildPoolXML(ctl, cmd, &name, &xml))
        return false;

    if (printXML) {
        vshPrint(ctl, "%s", xml);
        VIR_FREE(xml);
    } else {
        pool = virStoragePoolCreateXML(priv->conn, xml, flags);
        VIR_FREE(xml);

        if (pool != NULL) {
            vshPrintExtra(ctl, _("Pool %s created\n"), name);
            virStoragePoolFree(pool);
        } else {
            vshError(ctl, _("Failed to create pool %s"), name);
            return false;
        }
    }
    return true;
}

/*
 * "pool-define" command
 */
static const vshCmdInfo info_pool_define[] = {
    {.name = "help",
     .data = N_("define an inactive persistent storage pool or modify "
                "an existing persistent one from an XML file")
    },
    {.name = "desc",
     .data = N_("Define or modify a persistent storage pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_define[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML pool description")),

    {.name = NULL}
};

static bool
cmdPoolDefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *from = NULL;
    bool ret = true;
    char *buffer;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    pool = virStoragePoolDefineXML(priv->conn, buffer, 0);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrintExtra(ctl, _("Pool %s defined from %s\n"),
                      virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to define pool from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "pool-define-as" command
 */
static const vshCmdInfo info_pool_define_as[] = {
    {.name = "help",
     .data = N_("define a pool from a set of args")
    },
    {.name = "desc",
     .data = N_("Define a pool.")
    },
    {.name = NULL}
};

static bool
cmdPoolDefineAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    char *xml;
    bool printXML = vshCommandOptBool(cmd, "print-xml");
    virshControlPtr priv = ctl->privData;

    if (!virshBuildPoolXML(ctl, cmd, &name, &xml))
        return false;

    if (printXML) {
        vshPrint(ctl, "%s", xml);
        VIR_FREE(xml);
    } else {
        pool = virStoragePoolDefineXML(priv->conn, xml, 0);
        VIR_FREE(xml);

        if (pool != NULL) {
            vshPrintExtra(ctl, _("Pool %s defined\n"), name);
            virStoragePoolFree(pool);
        } else {
            vshError(ctl, _("Failed to define pool %s"), name);
            return false;
        }
    }
    return true;
}

/*
 * "pool-build" command
 */
static const vshCmdInfo info_pool_build[] = {
    {.name = "help",
     .data = N_("build a pool")
    },
    {.name = "desc",
     .data = N_("Build a given pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_build[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),
    VIRSH_COMMON_OPT_POOL_NO_OVERWRITE,
    VIRSH_COMMON_OPT_POOL_OVERWRITE,

    {.name = NULL}
};

static bool
cmdPoolBuild(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;
    unsigned int flags = 0;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (vshCommandOptBool(cmd, "no-overwrite"))
        flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;

    if (vshCommandOptBool(cmd, "overwrite"))
        flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;

    if (virStoragePoolBuild(pool, flags) == 0) {
        vshPrintExtra(ctl, _("Pool %s built\n"), name);
    } else {
        vshError(ctl, _("Failed to build pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);

    return ret;
}

/*
 * "pool-destroy" command
 */
static const vshCmdInfo info_pool_destroy[] = {
    {.name = "help",
     .data = N_("destroy (stop) a pool")
    },
    {.name = "desc",
     .data = N_("Forcefully stop a given pool. Raw data in the pool is untouched")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_destroy[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE),

    {.name = NULL}
};

static bool
cmdPoolDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolDestroy(pool) == 0) {
        vshPrintExtra(ctl, _("Pool %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

/*
 * "pool-delete" command
 */
static const vshCmdInfo info_pool_delete[] = {
    {.name = "help",
     .data = N_("delete a pool")
    },
    {.name = "desc",
     .data = N_("Delete a given pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_delete[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE),

    {.name = NULL}
};

static bool
cmdPoolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolDelete(pool, 0) == 0) {
        vshPrintExtra(ctl, _("Pool %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

/*
 * "pool-refresh" command
 */
static const vshCmdInfo info_pool_refresh[] = {
    {.name = "help",
     .data = N_("refresh a pool")
    },
    {.name = "desc",
     .data = N_("Refresh a given pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_refresh[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE),

    {.name = NULL}
};

static bool
cmdPoolRefresh(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolRefresh(pool, 0) == 0) {
        vshPrintExtra(ctl, _("Pool %s refreshed\n"), name);
    } else {
        vshError(ctl, _("Failed to refresh pool %s"), name);
        ret = false;
    }
    virStoragePoolFree(pool);

    return ret;
}

/*
 * "pool-dumpxml" command
 */
static const vshCmdInfo info_pool_dumpxml[] = {
    {.name = "help",
     .data = N_("pool information in XML")
    },
    {.name = "desc",
     .data = N_("Output the pool information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_dumpxml[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),

    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("show inactive defined XML")
    },
    {.name = NULL}
};

static bool
cmdPoolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    bool inactive = vshCommandOptBool(cmd, "inactive");
    unsigned int flags = 0;
    char *dump;

    if (inactive)
        flags |= VIR_STORAGE_XML_INACTIVE;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    dump = virStoragePoolGetXMLDesc(pool, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

static int
virshStoragePoolSorter(const void *a, const void *b)
{
    virStoragePoolPtr *pa = (virStoragePoolPtr *) a;
    virStoragePoolPtr *pb = (virStoragePoolPtr *) b;

    if (*pa && !*pb)
        return -1;

    if (!*pa)
        return *pb != NULL;

    return vshStrcasecmp(virStoragePoolGetName(*pa),
                         virStoragePoolGetName(*pb));
}

struct virshStoragePoolList {
    virStoragePoolPtr *pools;
    size_t npools;
};
typedef struct virshStoragePoolList *virshStoragePoolListPtr;

static void
virshStoragePoolListFree(virshStoragePoolListPtr list)
{
    size_t i;

    if (list && list->pools) {
        for (i = 0; i < list->npools; i++) {
            if (list->pools[i])
                virStoragePoolFree(list->pools[i]);
        }
        VIR_FREE(list->pools);
    }
    VIR_FREE(list);
}

static virshStoragePoolListPtr
virshStoragePoolListCollect(vshControl *ctl,
                            unsigned int flags)
{
    virshStoragePoolListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    int ret;
    char **names = NULL;
    virStoragePoolPtr pool;
    bool success = false;
    size_t deleted = 0;
    int persistent;
    int autostart;
    int nActivePools = 0;
    int nInactivePools = 0;
    int nAllPools = 0;
    virshControlPtr priv = ctl->privData;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllStoragePools(priv->conn,
                                             &list->pools,
                                             flags)) >= 0) {
        list->npools = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    if (last_error && last_error->code ==  VIR_ERR_INVALID_ARG) {
        /* try the new API again but mask non-guaranteed flags */
        unsigned int newflags = flags & (VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE |
                                         VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE);
        vshResetLibvirtError();
        if ((ret = virConnectListAllStoragePools(priv->conn, &list->pools,
                                                 newflags)) >= 0) {
            list->npools = ret;
            goto filter;
        }
    }

    /* there was an error during the first or second call */
    vshError(ctl, "%s", _("Failed to list pools"));
    goto cleanup;


 fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    /* There is no way to get the pool type */
    if (VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE)) {
        vshError(ctl, "%s", _("Filtering using --type is not supported "
                              "by this libvirt"));
        goto cleanup;
    }

    /* Get the number of active pools */
    if (!VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)) {
        if ((nActivePools = virConnectNumOfStoragePools(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of active pools "));
            goto cleanup;
        }
    }

    /* Get the number of inactive pools */
    if (!VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE)) {
        if ((nInactivePools = virConnectNumOfDefinedStoragePools(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of inactive pools"));
            goto cleanup;
        }
    }

    nAllPools = nActivePools + nInactivePools;

    if (nAllPools == 0)
        return list;

    names = vshMalloc(ctl, sizeof(char *) * nAllPools);

    /* Retrieve a list of active storage pool names */
    if (!VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)) {
        if (virConnectListStoragePools(priv->conn,
                                       names, nActivePools) < 0) {
            vshError(ctl, "%s", _("Failed to list active pools"));
            goto cleanup;
        }
    }

    /* Add the inactive storage pools to the end of the name list */
    if (!VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)) {
        if (virConnectListDefinedStoragePools(priv->conn,
                                              &names[nActivePools],
                                              nInactivePools) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive pools"));
            goto cleanup;
        }
    }

    list->pools = vshMalloc(ctl, sizeof(virStoragePoolPtr) * (nAllPools));
    list->npools = 0;

    /* get active pools */
    for (i = 0; i < nActivePools; i++) {
        if (!(pool = virStoragePoolLookupByName(priv->conn, names[i])))
            continue;
        list->pools[list->npools++] = pool;
    }

    /* get inactive pools */
    for (i = 0; i < nInactivePools; i++) {
        if (!(pool = virStoragePoolLookupByName(priv->conn, names[i])))
            continue;
        list->pools[list->npools++] = pool;
    }

    /* truncate pools that weren't found */
    deleted = nAllPools - list->npools;

 filter:
    /* filter list the list if the list was acquired by fallback means */
    for (i = 0; i < list->npools; i++) {
        pool = list->pools[i];

        /* persistence filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT)) {
            if ((persistent = virStoragePoolIsPersistent(pool)) < 0) {
                vshError(ctl, "%s", _("Failed to get pool persistence info"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT) && persistent) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT) && !persistent)))
                goto remove_entry;
        }

        /* autostart filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART)) {
            if (virStoragePoolGetAutostart(pool, &autostart) < 0) {
                vshError(ctl, "%s", _("Failed to get pool autostart state"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART) && autostart) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART) && !autostart)))
                goto remove_entry;
        }

        /* the pool matched all filters, it may stay */
        continue;

 remove_entry:
        /* the pool has to be removed as it failed one of the filters */
        virStoragePoolFree(list->pools[i]);
        list->pools[i] = NULL;
        deleted++;
    }

 finished:
    /* sort the list */
    if (list->pools && list->npools)
        qsort(list->pools, list->npools,
              sizeof(*list->pools), virshStoragePoolSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->pools, list->npools, deleted);

    success = true;

 cleanup:
    for (i = 0; i < nAllPools; i++)
        VIR_FREE(names[i]);

    if (!success) {
        virshStoragePoolListFree(list);
        list = NULL;
    }

    VIR_FREE(names);
    return list;
}


VIR_ENUM_DECL(virshStoragePoolState);
VIR_ENUM_IMPL(virshStoragePoolState,
              VIR_STORAGE_POOL_STATE_LAST,
              N_("inactive"),
              N_("building"),
              N_("running"),
              N_("degraded"),
              N_("inaccessible"));

static const char *
virshStoragePoolStateToString(int state)
{
    const char *str = virshStoragePoolStateTypeToString(state);
    return str ? _(str) : _("unknown");
}


/*
 * "pool-list" command
 */
static const vshCmdInfo info_pool_list[] = {
    {.name = "help",
     .data = N_("list pools")
    },
    {.name = "desc",
     .data = N_("Returns list of pools.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_list[] = {
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive pools")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive & active pools")
    },
    {.name = "transient",
     .type = VSH_OT_BOOL,
     .help = N_("list transient pools")
    },
    {.name = "persistent",
     .type = VSH_OT_BOOL,
     .help = N_("list persistent pools")
    },
    {.name = "autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list pools with autostart enabled")
    },
    {.name = "no-autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list pools with autostart disabled")
    },
    {.name = "type",
     .type = VSH_OT_STRING,
     .completer = virshPoolTypeCompleter,
     .help = N_("only list pool of specified type(s) (if supported)")
    },
    {.name = "details",
     .type = VSH_OT_BOOL,
     .help = N_("display extended details for pools")
    },
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("list UUID of active pools only")
    },
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list name of active pools only")
    },
    {.name = NULL}
};

static bool
cmdPoolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStoragePoolInfo info;
    size_t i;
    bool ret = false;
    struct poolInfoText {
        char *state;
        char *autostart;
        char *persistent;
        char *capacity;
        char *allocation;
        char *available;
    };
    struct poolInfoText *poolInfoTexts = NULL;
    unsigned int flags = VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE;
    virshStoragePoolListPtr list = NULL;
    const char *type = NULL;
    bool details = vshCommandOptBool(cmd, "details");
    bool inactive, all;
    bool uuid = false;
    bool name = false;
    vshTablePtr table = NULL;

    inactive = vshCommandOptBool(cmd, "inactive");
    all = vshCommandOptBool(cmd, "all");

    if (inactive)
        flags = VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE;

    if (all)
        flags = VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE |
                VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE;

    if (vshCommandOptBool(cmd, "autostart"))
        flags |= VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART;

    if (vshCommandOptBool(cmd, "no-autostart"))
        flags |= VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART;

    if (vshCommandOptBool(cmd, "persistent"))
        flags |= VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT;

    if (vshCommandOptBool(cmd, "transient"))
        flags |= VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT;

    if (vshCommandOptBool(cmd, "uuid"))
        uuid = true;

    if (vshCommandOptBool(cmd, "name"))
        name = true;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        return false;

    VSH_EXCLUSIVE_OPTIONS("details", "uuid");
    VSH_EXCLUSIVE_OPTIONS("details", "name");

    if (type) {
        int poolType = -1;
        char **poolTypes = NULL;
        int npoolTypes = 0;

        if ((npoolTypes = vshStringToArray(type, &poolTypes)) < 0)
            return false;

        for (i = 0; i < npoolTypes; i++) {
            if ((poolType = virStoragePoolTypeFromString(poolTypes[i])) < 0) {
                vshError(ctl, _("Invalid pool type '%s'"), poolTypes[i]);
                virStringListFree(poolTypes);
                return false;
            }

            switch ((virStoragePoolType) poolType) {
            case VIR_STORAGE_POOL_DIR:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_DIR;
                break;
            case VIR_STORAGE_POOL_FS:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_FS;
                break;
            case VIR_STORAGE_POOL_NETFS:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_NETFS;
                break;
            case VIR_STORAGE_POOL_LOGICAL:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL;
                break;
            case VIR_STORAGE_POOL_DISK:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_DISK;
                break;
            case VIR_STORAGE_POOL_ISCSI:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI;
                break;
            case VIR_STORAGE_POOL_ISCSI_DIRECT:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI_DIRECT;
                break;
            case VIR_STORAGE_POOL_SCSI:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_SCSI;
                break;
            case VIR_STORAGE_POOL_MPATH:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_MPATH;
                break;
            case VIR_STORAGE_POOL_RBD:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_RBD;
                break;
            case VIR_STORAGE_POOL_SHEEPDOG:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG;
                break;
            case VIR_STORAGE_POOL_GLUSTER:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER;
                break;
            case VIR_STORAGE_POOL_ZFS:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_ZFS;
                break;
            case VIR_STORAGE_POOL_VSTORAGE:
                flags |= VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE;
                break;
            case VIR_STORAGE_POOL_LAST:
                break;
            }
        }
        virStringListFree(poolTypes);
    }

    if (!(list = virshStoragePoolListCollect(ctl, flags)))
        goto cleanup;

    poolInfoTexts = vshCalloc(ctl, list->npools, sizeof(*poolInfoTexts));

    /* Collect the storage pool information for display */
    for (i = 0; i < list->npools; i++) {
        int autostart = 0, persistent = 0;

        /* Retrieve the autostart status of the pool */
        if (virStoragePoolGetAutostart(list->pools[i], &autostart) < 0)
            poolInfoTexts[i].autostart = vshStrdup(ctl, _("no autostart"));
        else
            poolInfoTexts[i].autostart = vshStrdup(ctl, autostart ?
                                                    _("yes") : _("no"));

        /* Retrieve the persistence status of the pool */
        if (details) {
            persistent = virStoragePoolIsPersistent(list->pools[i]);
            vshDebug(ctl, VSH_ERR_DEBUG, "Persistent flag value: %d\n",
                     persistent);
            if (persistent < 0)
                poolInfoTexts[i].persistent = vshStrdup(ctl, _("unknown"));
            else
                poolInfoTexts[i].persistent = vshStrdup(ctl, persistent ?
                                                         _("yes") : _("no"));
        }

        /* Collect further extended information about the pool */
        if (virStoragePoolGetInfo(list->pools[i], &info) != 0) {
            /* Something went wrong retrieving pool info, cope with it */
            vshError(ctl, "%s", _("Could not retrieve pool information"));
            poolInfoTexts[i].state = vshStrdup(ctl, _("unknown"));
            if (details) {
                poolInfoTexts[i].capacity = vshStrdup(ctl, _("unknown"));
                poolInfoTexts[i].allocation = vshStrdup(ctl, _("unknown"));
                poolInfoTexts[i].available = vshStrdup(ctl, _("unknown"));
            }
        } else {
            /* Decide which state string to display */
            if (details) {
                const char *state = virshStoragePoolStateToString(info.state);

                poolInfoTexts[i].state = vshStrdup(ctl, state);

                /* Create the pool size related strings */
                if (info.state == VIR_STORAGE_POOL_RUNNING ||
                    info.state == VIR_STORAGE_POOL_DEGRADED) {
                    double val;
                    const char *unit;

                    val = vshPrettyCapacity(info.capacity, &unit);
                    if (virAsprintf(&poolInfoTexts[i].capacity,
                                    "%.2lf %s", val, unit) < 0)
                        goto cleanup;

                    val = vshPrettyCapacity(info.allocation, &unit);
                    if (virAsprintf(&poolInfoTexts[i].allocation,
                                    "%.2lf %s", val, unit) < 0)
                        goto cleanup;

                    val = vshPrettyCapacity(info.available, &unit);
                    if (virAsprintf(&poolInfoTexts[i].available,
                                    "%.2lf %s", val, unit) < 0)
                        goto cleanup;
                } else {
                    /* Capacity related information isn't available */
                    poolInfoTexts[i].capacity = vshStrdup(ctl, _("-"));
                    poolInfoTexts[i].allocation = vshStrdup(ctl, _("-"));
                    poolInfoTexts[i].available = vshStrdup(ctl, _("-"));
                }
            } else {
                /* --details option was not specified, only active/inactive
                 * state strings are used */
                if (virStoragePoolIsActive(list->pools[i]))
                    poolInfoTexts[i].state = vshStrdup(ctl, _("active"));
                else
                    poolInfoTexts[i].state = vshStrdup(ctl, _("inactive"));
           }
        }
    }

    /* If the --details option wasn't selected, we output the pool
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        if (uuid || name) {
            for (i = 0; i < list->npools; i++) {
                if (uuid) {
                    char uuid_str[VIR_UUID_STRING_BUFLEN];
                    virStoragePoolGetUUIDString(list->pools[i], uuid_str);
                    vshPrint(ctl, "%-36s%c", uuid_str, name ? ' ': '\n');
                }
                if (name) {
                    const char *name_str =
                        virStoragePoolGetName(list->pools[i]);
                    vshPrint(ctl, "%-20s\n", name_str);
                }
            }
            ret = true;
            goto cleanup;
        }

        /* Output old style header */
        table = vshTableNew(_("Name"), _("State"), _("Autostart"), NULL);
        if (!table)
            goto cleanup;

        /* Output old style pool info */
        for (i = 0; i < list->npools; i++) {
            const char *name_str = virStoragePoolGetName(list->pools[i]);
            if (vshTableRowAppend(table,
                                  name_str,
                                  poolInfoTexts[i].state,
                                  poolInfoTexts[i].autostart,
                                  NULL) < 0)
                goto cleanup;
        }

        vshTablePrintToStdout(table, ctl);

        /* Cleanup and return */
        ret = true;
        goto cleanup;
    }

    /* We only get here if the --details option was selected. */

    /* Insert the header into table */
    table = vshTableNew(_("Name"), _("State"), _("Autostart"), _("Persistent"),
                        _("Capacity"), _("Allocation"), _("Available"), NULL);
    if (!table)
        goto cleanup;

    /* Insert the pool info rows into table*/
    for (i = 0; i < list->npools; i++) {
        if (vshTableRowAppend(table,
                              virStoragePoolGetName(list->pools[i]),
                              poolInfoTexts[i].state,
                              poolInfoTexts[i].autostart,
                              poolInfoTexts[i].persistent,
                              poolInfoTexts[i].capacity,
                              poolInfoTexts[i].allocation,
                              poolInfoTexts[i].available,
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    /* Cleanup and return */
    ret = true;

 cleanup:
    vshTableFree(table);
    if (list && list->npools) {
        for (i = 0; i < list->npools; i++) {
            VIR_FREE(poolInfoTexts[i].state);
            VIR_FREE(poolInfoTexts[i].autostart);
            VIR_FREE(poolInfoTexts[i].persistent);
            VIR_FREE(poolInfoTexts[i].capacity);
            VIR_FREE(poolInfoTexts[i].allocation);
            VIR_FREE(poolInfoTexts[i].available);
        }
    }
    VIR_FREE(poolInfoTexts);

    virshStoragePoolListFree(list);
    return ret;
}

/*
 * "find-storage-pool-sources-as" command
 */
static const vshCmdInfo info_find_storage_pool_sources_as[] = {
    {.name = "help",
     .data = N_("find potential storage pool sources")
    },
    {.name = "desc",
     .data = N_("Returns XML <sources> document.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources_as[] = {
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("type of storage pool sources to find")
    },
    {.name = "host",
     .type = VSH_OT_STRING,
     .help = N_("optional host to query")
    },
    {.name = "port",
     .type = VSH_OT_STRING,
     .help = N_("optional port to query")
    },
    {.name = "initiator",
     .type = VSH_OT_STRING,
     .help = N_("optional initiator IQN to use for query")
    },
    {.name = NULL}
};

static bool
cmdPoolDiscoverSourcesAs(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    const char *type = NULL, *host = NULL;
    char *srcSpec = NULL;
    char *srcList;
    const char *initiator = NULL;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "host", &host) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "initiator", &initiator) < 0)
        return false;

    if (host) {
        const char *port = NULL;
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        if (vshCommandOptStringReq(ctl, cmd, "port", &port) < 0) {
            vshError(ctl, "%s", _("missing argument"));
            virBufferFreeAndReset(&buf);
            return false;
        }
        virBufferAddLit(&buf, "<source>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<host name='%s'", host);
        if (port)
            virBufferAsprintf(&buf, " port='%s'", port);
        virBufferAddLit(&buf, "/>\n");
        if (initiator) {
            virBufferAddLit(&buf, "<initiator>\n");
            virBufferAdjustIndent(&buf, 2);
            virBufferAsprintf(&buf, "<iqn name='%s'/>\n", initiator);
            virBufferAdjustIndent(&buf, -2);
            virBufferAddLit(&buf, "</initiator>\n");
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</source>\n");
        if (virBufferError(&buf)) {
            vshError(ctl, "%s", _("Out of memory"));
            return false;
        }
        srcSpec = virBufferContentAndReset(&buf);
    }

    srcList = virConnectFindStoragePoolSources(priv->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return false;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return true;
}

/*
 * "find-storage-pool-sources" command
 */
static const vshCmdInfo info_find_storage_pool_sources[] = {
    {.name = "help",
     .data = N_("discover potential storage pool sources")
    },
    {.name = "desc",
     .data = N_("Returns XML <sources> document.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources[] = {
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("type of storage pool sources to discover")
    },
    {.name = "srcSpec",
     .type = VSH_OT_STRING,
     .help = N_("optional file of source xml to query for pools")
    },
    {.name = NULL}
};

static bool
cmdPoolDiscoverSources(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    const char *type = NULL, *srcSpecFile = NULL;
    char *srcSpec = NULL, *srcList;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "srcSpec", &srcSpecFile) < 0)
        return false;

    if (srcSpecFile && virFileReadAll(srcSpecFile, VSH_MAX_XML_FILE,
                                      &srcSpec) < 0)
        return false;

    srcList = virConnectFindStoragePoolSources(priv->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return false;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return true;
}

/*
 * "pool-info" command
 */
static const vshCmdInfo info_pool_info[] = {
    {.name = "help",
     .data = N_("storage pool information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the storage pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_info[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),

    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("Reture pool info in bytes"),
    },
    {.name = NULL}
};

static bool
cmdPoolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolInfo info;
    virStoragePoolPtr pool;
    int autostart = 0;
    int persistent = 0;
    bool ret = true;
    bool bytes = false;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    bytes = vshCommandOptBool(cmd, "bytes");

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStoragePoolGetName(pool));

    if (virStoragePoolGetUUIDString(pool, &uuid[0]) == 0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

    if (virStoragePoolGetInfo(pool, &info) == 0) {
        double val;
        const char *unit;
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 virshStoragePoolStateToString(info.state));

        /* Check and display whether the pool is persistent or not */
        persistent = virStoragePoolIsPersistent(pool);
        vshDebug(ctl, VSH_ERR_DEBUG, "Pool persistent flag value: %d\n",
                 persistent);
        if (persistent < 0)
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"),  _("unknown"));
        else
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

        /* Check and display whether the pool is autostarted or not */
        if (virStoragePoolGetAutostart(pool, &autostart) < 0)
            vshPrint(ctl, "%-15s %s\n", _("Autostart:"), _("no autostart"));
        else
            vshPrint(ctl, "%-15s %s\n", _("Autostart:"), autostart ? _("yes") : _("no"));

        if (info.state == VIR_STORAGE_POOL_RUNNING ||
            info.state == VIR_STORAGE_POOL_DEGRADED) {
            if (bytes) {
                vshPrint(ctl, "%-15s %llu\n", _("Capacity:"), info.capacity);
                vshPrint(ctl, "%-15s %llu\n", _("Allocation:"), info.allocation);
                vshPrint(ctl, "%-15s %llu\n", _("Available:"), info.available);
            } else {
                val = vshPrettyCapacity(info.capacity, &unit);
                vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

                val = vshPrettyCapacity(info.allocation, &unit);
                vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);

                val = vshPrettyCapacity(info.available, &unit);
                vshPrint(ctl, "%-15s %2.2lf %s\n", _("Available:"), val, unit);
            }
        }
    } else {
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

/*
 * "pool-name" command
 */
static const vshCmdInfo info_pool_name[] = {
    {.name = "help",
     .data = N_("convert a pool UUID to pool name")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_name[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),

    {.name = NULL}
};

static bool
cmdPoolName(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;

    if (!(pool = virshCommandOptPoolBy(ctl, cmd, "pool", NULL, VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virStoragePoolGetName(pool));
    virStoragePoolFree(pool);
    return true;
}

/*
 * "pool-start" command
 */
static const vshCmdInfo info_pool_start[] = {
    {.name = "help",
     .data = N_("start a (previously defined) inactive pool")
    },
    {.name = "desc",
     .data = N_("Start a pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_start[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE),
    VIRSH_COMMON_OPT_POOL_BUILD,
    VIRSH_COMMON_OPT_POOL_NO_OVERWRITE,
    VIRSH_COMMON_OPT_POOL_OVERWRITE,

    {.name = NULL}
};

static bool
cmdPoolStart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name = NULL;
    bool build;
    bool overwrite;
    bool no_overwrite;
    unsigned int flags = 0;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
         return false;

    build = vshCommandOptBool(cmd, "build");
    overwrite = vshCommandOptBool(cmd, "overwrite");
    no_overwrite = vshCommandOptBool(cmd, "no-overwrite");

    VSH_EXCLUSIVE_OPTIONS_EXPR("overwrite", overwrite,
                               "no-overwrite", no_overwrite);

    if (build)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD;
    if (overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE;
    if (no_overwrite)
        flags |= VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE;

    if (virStoragePoolCreate(pool, flags) == 0) {
        vshPrintExtra(ctl, _("Pool %s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

/*
 * "pool-undefine" command
 */
static const vshCmdInfo info_pool_undefine[] = {
    {.name = "help",
     .data = N_("undefine an inactive pool")
    },
    {.name = "desc",
     .data = N_("Undefine the configuration for an inactive pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_undefine[] = {
    VIRSH_COMMON_OPT_POOL_FULL(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT),

    {.name = NULL}
};

static bool
cmdPoolUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolUndefine(pool) == 0) {
        vshPrintExtra(ctl, _("Pool %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}

/*
 * "pool-uuid" command
 */
static const vshCmdInfo info_pool_uuid[] = {
    {.name = "help",
     .data = N_("convert a pool name to pool UUID")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_uuid[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),

    {.name = NULL}
};

static bool
cmdPoolUuid(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!(pool = virshCommandOptPoolBy(ctl, cmd, "pool", NULL, VIRSH_BYNAME)))
        return false;

    if (virStoragePoolGetUUIDString(pool, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get pool UUID"));

    virStoragePoolFree(pool);
    return true;
}

/*
 * "pool-edit" command
 */
static const vshCmdInfo info_pool_edit[] = {
    {.name = "help",
     .data = N_("edit XML configuration for a storage pool")
    },
    {.name = "desc",
     .data = N_("Edit the XML configuration for a storage pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_edit[] = {
    VIRSH_COMMON_OPT_POOL_FULL(0),

    {.name = NULL}
};

static bool
cmdPoolEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virStoragePoolPtr pool = NULL;
    virStoragePoolPtr pool_edited = NULL;
    unsigned int flags = VIR_STORAGE_XML_INACTIVE;
    char *tmp_desc = NULL;
    virshControlPtr priv = ctl->privData;

    pool = virshCommandOptPool(ctl, cmd, "pool", NULL);
    if (pool == NULL)
        goto cleanup;

    /* Some old daemons don't support _INACTIVE flag */
    if (!(tmp_desc = virStoragePoolGetXMLDesc(pool, flags))) {
        if (last_error->code == VIR_ERR_INVALID_ARG) {
            flags &= ~VIR_STORAGE_XML_INACTIVE;
            vshResetLibvirtError();
        } else {
            goto cleanup;
        }
    } else {
        VIR_FREE(tmp_desc);
    }

#define EDIT_GET_XML virStoragePoolGetXMLDesc(pool, flags)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Pool %s XML configuration not changed.\n"), \
                 virStoragePoolGetName(pool)); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (pool_edited = virStoragePoolDefineXML(priv->conn, doc_edited, 0))
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("Pool %s XML configuration edited.\n"),
                  virStoragePoolGetName(pool_edited));

    ret = true;

 cleanup:
    if (pool)
        virStoragePoolFree(pool);
    if (pool_edited)
        virStoragePoolFree(pool_edited);

    return ret;
}

/*
 * "pool-event" command
 */
VIR_ENUM_DECL(virshPoolEvent);
VIR_ENUM_IMPL(virshPoolEvent,
              VIR_STORAGE_POOL_EVENT_LAST,
              N_("Defined"),
              N_("Undefined"),
              N_("Started"),
              N_("Stopped"),
              N_("Created"),
              N_("Deleted"));

static const char *
virshPoolEventToString(int event)
{
    const char *str = virshPoolEventTypeToString(event);
    return str ? _(str) : _("unknown");
}

struct virshPoolEventData {
    vshControl *ctl;
    bool loop;
    bool timestamp;
    int count;
    virshPoolEventCallback *cb;
};
typedef struct virshPoolEventData virshPoolEventData;


static void
vshEventLifecyclePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virStoragePoolPtr pool,
                       int event,
                       int detail ATTRIBUTE_UNUSED,
                       void *opaque)
{
    virshPoolEventData *data = opaque;

    if (!data->loop && data->count)
        return;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%s: event 'lifecycle' for storage pool %s: %s\n"),
                 timestamp,
                 virStoragePoolGetName(pool),
                 virshPoolEventToString(event));
    } else {
        vshPrint(data->ctl, _("event 'lifecycle' for storage pool %s: %s\n"),
                 virStoragePoolGetName(pool),
                 virshPoolEventToString(event));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

static void
vshEventGenericPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virStoragePoolPtr pool,
                     void *opaque)
{
    virshPoolEventData *data = opaque;

    if (!data->loop && data->count)
        return;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%s: event '%s' for storage pool %s\n"),
                 timestamp,
                 data->cb->name,
                 virStoragePoolGetName(pool));
    } else {
        vshPrint(data->ctl, _("event '%s' for storage pool %s\n"),
                 data->cb->name,
                 virStoragePoolGetName(pool));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

virshPoolEventCallback virshPoolEventCallbacks[] = {
    { "lifecycle",
      VIR_STORAGE_POOL_EVENT_CALLBACK(vshEventLifecyclePrint), },
    { "refresh", vshEventGenericPrint, }
};
verify(VIR_STORAGE_POOL_EVENT_ID_LAST == ARRAY_CARDINALITY(virshPoolEventCallbacks));


static const vshCmdInfo info_pool_event[] = {
    {.name = "help",
     .data = N_("Storage Pool Events")
    },
    {.name = "desc",
     .data = N_("List event types, or wait for storage pool events to occur")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_event[] = {
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("filter by storage pool name or uuid")
    },
    {.name = "event",
     .type = VSH_OT_STRING,
     .completer = virshPoolEventNameCompleter,
     .help = N_("which event type to wait for")
    },
    {.name = "loop",
     .type = VSH_OT_BOOL,
     .help = N_("loop until timeout or interrupt, rather than one-shot")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("timeout seconds")
    },
    {.name = "list",
     .type = VSH_OT_BOOL,
     .help = N_("list valid event types")
    },
    {.name = "timestamp",
     .type = VSH_OT_BOOL,
     .help = N_("show timestamp for each printed event")
    },
    {.name = NULL}
};

static bool
cmdPoolEvent(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool = NULL;
    bool ret = false;
    int eventId = -1;
    int timeout = 0;
    virshPoolEventData data;
    const char *eventName = NULL;
    int event;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "list")) {
        size_t i;

        for (i = 0; i < VIR_STORAGE_POOL_EVENT_ID_LAST; i++)
            vshPrint(ctl, "%s\n", virshPoolEventCallbacks[i].name);
        return true;
    }

    if (vshCommandOptStringReq(ctl, cmd, "event", &eventName) < 0)
        return false;
    if (!eventName) {
        vshError(ctl, "%s", _("either --list or --event <type> is required"));
        return false;
    }

    for (event = 0; event < VIR_STORAGE_POOL_EVENT_ID_LAST; event++)
        if (STREQ(eventName, virshPoolEventCallbacks[event].name))
            break;
    if (event == VIR_STORAGE_POOL_EVENT_ID_LAST) {
        vshError(ctl, _("unknown event type %s"), eventName);
        return false;
    }

    data.ctl = ctl;
    data.loop = vshCommandOptBool(cmd, "loop");
    data.timestamp = vshCommandOptBool(cmd, "timestamp");
    data.count = 0;
    data.cb = &virshPoolEventCallbacks[event];
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (vshCommandOptBool(cmd, "pool"))
        pool = virshCommandOptPool(ctl, cmd, "pool", NULL);
    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    if ((eventId = virConnectStoragePoolEventRegisterAny(priv->conn, pool, event,
                                                         data.cb->cb,
                                                         &data, NULL)) < 0)
        goto cleanup;
    switch (vshEventWait(ctl)) {
    case VSH_EVENT_INTERRUPT:
        vshPrint(ctl, "%s", _("event loop interrupted\n"));
        break;
    case VSH_EVENT_TIMEOUT:
        vshPrint(ctl, "%s", _("event loop timed out\n"));
        break;
    case VSH_EVENT_DONE:
        break;
    default:
        goto cleanup;
    }
    vshPrint(ctl, _("events received: %d\n"), data.count);
    if (data.count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (eventId >= 0 &&
        virConnectStoragePoolEventDeregisterAny(priv->conn, eventId) < 0)
        ret = false;
    if (pool)
        virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-capabilities" command
 */
static const vshCmdInfo info_pool_capabilities[] = {
    {.name = "help",
     .data = N_("storage pool capabilities")
    },
    {.name = "desc",
     .data = N_("Returns capabilities of storage pool support.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_pool_capabilities[] = {
    {.name = NULL}
};

static bool
cmdPoolCapabilities(vshControl *ctl,
                    const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const unsigned int flags = 0; /* No flags so far */
    virshControlPtr priv = ctl->privData;
    VIR_AUTOFREE(char *) caps = NULL;

    caps = virConnectGetStoragePoolCapabilities(priv->conn, flags);
    if (!caps) {
        vshError(ctl, "%s", _("failed to get storage pool capabilities"));
        return false;
    }

    vshPrint(ctl, "%s\n", caps);
    return true;
}


const vshCmdDef storagePoolCmds[] = {
    {.name = "find-storage-pool-sources-as",
     .handler = cmdPoolDiscoverSourcesAs,
     .opts = opts_find_storage_pool_sources_as,
     .info = info_find_storage_pool_sources_as,
     .flags = 0
    },
    {.name = "find-storage-pool-sources",
     .handler = cmdPoolDiscoverSources,
     .opts = opts_find_storage_pool_sources,
     .info = info_find_storage_pool_sources,
     .flags = 0
    },
    {.name = "pool-autostart",
     .handler = cmdPoolAutostart,
     .opts = opts_pool_autostart,
     .info = info_pool_autostart,
     .flags = 0
    },
    {.name = "pool-build",
     .handler = cmdPoolBuild,
     .opts = opts_pool_build,
     .info = info_pool_build,
     .flags = 0
    },
    {.name = "pool-create-as",
     .handler = cmdPoolCreateAs,
     .opts = opts_pool_create_as,
     .info = info_pool_create_as,
     .flags = 0
    },
    {.name = "pool-create",
     .handler = cmdPoolCreate,
     .opts = opts_pool_create,
     .info = info_pool_create,
     .flags = 0
    },
    {.name = "pool-define-as",
     .handler = cmdPoolDefineAs,
     .opts = opts_pool_define_as,
     .info = info_pool_define_as,
     .flags = 0
    },
    {.name = "pool-define",
     .handler = cmdPoolDefine,
     .opts = opts_pool_define,
     .info = info_pool_define,
     .flags = 0
    },
    {.name = "pool-delete",
     .handler = cmdPoolDelete,
     .opts = opts_pool_delete,
     .info = info_pool_delete,
     .flags = 0
    },
    {.name = "pool-destroy",
     .handler = cmdPoolDestroy,
     .opts = opts_pool_destroy,
     .info = info_pool_destroy,
     .flags = 0
    },
    {.name = "pool-dumpxml",
     .handler = cmdPoolDumpXML,
     .opts = opts_pool_dumpxml,
     .info = info_pool_dumpxml,
     .flags = 0
    },
    {.name = "pool-edit",
     .handler = cmdPoolEdit,
     .opts = opts_pool_edit,
     .info = info_pool_edit,
     .flags = 0
    },
    {.name = "pool-info",
     .handler = cmdPoolInfo,
     .opts = opts_pool_info,
     .info = info_pool_info,
     .flags = 0
    },
    {.name = "pool-list",
     .handler = cmdPoolList,
     .opts = opts_pool_list,
     .info = info_pool_list,
     .flags = 0
    },
    {.name = "pool-name",
     .handler = cmdPoolName,
     .opts = opts_pool_name,
     .info = info_pool_name,
     .flags = 0
    },
    {.name = "pool-refresh",
     .handler = cmdPoolRefresh,
     .opts = opts_pool_refresh,
     .info = info_pool_refresh,
     .flags = 0
    },
    {.name = "pool-start",
     .handler = cmdPoolStart,
     .opts = opts_pool_start,
     .info = info_pool_start,
     .flags = 0
    },
    {.name = "pool-undefine",
     .handler = cmdPoolUndefine,
     .opts = opts_pool_undefine,
     .info = info_pool_undefine,
     .flags = 0
    },
    {.name = "pool-uuid",
     .handler = cmdPoolUuid,
     .opts = opts_pool_uuid,
     .info = info_pool_uuid,
     .flags = 0
    },
    {.name = "pool-event",
     .handler = cmdPoolEvent,
     .opts = opts_pool_event,
     .info = info_pool_event,
     .flags = 0
    },
    {.name = "pool-capabilities",
     .handler = cmdPoolCapabilities,
     .opts = opts_pool_capabilities,
     .info = info_pool_capabilities,
     .flags = 0
    },
    {.name = NULL}
};
