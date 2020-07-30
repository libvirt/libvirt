/*
 * jailhouse_driver.c: Implementation of driver for Jailhouse hypervisor
 *
 * Copyright (C) 2020 Prakhar Bansal
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
#include <string.h>

#include "configmake.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virtypedparam.h"
#include "virerror.h"
#include "virstring.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"
#include "vircommand.h"
#include "virpidfile.h"
#include "access/viraccessapicheck.h"
#include "virdomainobjlist.h"

#include "jailhouse_driver.h"

#define VIR_FROM_THIS VIR_FROM_JAILHOUSE

VIR_LOG_INIT("jailhouse.jailhouse_driver");

static virClassPtr virJailhouseDriverConfigClass;
static void virJailhouseDriverConfigDispose(void *obj);

static virJailhouseDriverPtr jailhouse_driver;

static int virJailhouseConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virJailhouseDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virJailhouseConfig);


static virJailhouseDriverConfigPtr
virJailhouseDriverConfigNew(void)
{
    virJailhouseDriverConfigPtr cfg;

    if (virJailhouseConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virJailhouseDriverConfigClass)))
        return NULL;

    cfg->stateDir = g_strdup(JAILHOUSE_STATE_DIR);

    cfg->sys_config_file_path = g_strdup(DATADIR "/jailhouse/system.cell");

    cfg->cell_config_dir = g_strdup(DATADIR "/jailhouse/cells");

    return cfg;
}

static void virJailhouseDriverConfigDispose(void *obj)
{

    virJailhouseDriverConfigPtr cfg = obj;

    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->sys_config_file_path);
    VIR_FREE(cfg->cell_config_dir);
}

static int
jailhouseLoadConf(virJailhouseDriverConfigPtr config)
{
    g_autoptr(virConf) conf = NULL;

    if (!virFileExists(JAILHOUSE_CONFIG_FILE))
        return 0;

    if (!(conf = virConfReadFile(JAILHOUSE_CONFIG_FILE, 0)))
        return -1;

    if (virConfGetValueString(conf, "system_config",
                              &config->sys_config_file_path) < 0)
        return -1;

    if (virConfGetValueString(conf, "non_root_cells_dir",
                              &config->cell_config_dir) < 0)
        return -1;

    return 1;
}

static int
jailhouseCreateAndLoadCells(virJailhouseDriverPtr driver)
{
    if (!driver->config ||
        !driver->config->cell_config_dir ||
        strlen(driver->config->cell_config_dir) == 0)
        return -1;

    // Create all cells in the hypervisor.
    if (createJailhouseCells(driver->config->cell_config_dir) < 0)
        return -1;

    // Get all cells created above.
    driver->cell_info_list = getJailhouseCellsInfo();

    return 0;
}

static void
jailhouseFreeDriver(virJailhouseDriverPtr driver)
{
    if (!driver)
        return;

    virMutexDestroy(&driver->lock);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->config);
    VIR_FREE(driver);
}

static virDrvOpenStatus
jailhouseConnectOpen(virConnectPtr conn,
                     virConnectAuthPtr auth G_GNUC_UNUSED,
                     virConfPtr conf G_GNUC_UNUSED, unsigned int flags)
{
    uid_t uid = geteuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!virConnectValidateURIPath(conn->uri->path, "jailhouse", uid == 0))
        return VIR_DRV_OPEN_ERROR;

    if (!jailhouse_driver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Jailhouse driver state is not initialized."));
        return VIR_DRV_OPEN_ERROR;
    }

    conn->privateData = jailhouse_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

#define UNUSED(x) (void)(x)

static int
jailhouseConnectClose(virConnectPtr conn)
{
   conn->privateData = NULL;

   return 0;
}

static int
jailhouseStateCleanup(void)
{
    if (!jailhouse_driver)
       return -1;

    if (jailhouse_driver->lockFD != -1)
        virPidFileRelease(jailhouse_driver->config->stateDir,
                          "driver", jailhouse_driver->lockFD);

    virMutexDestroy(&jailhouse_driver->lock);

    jailhouseFreeDriver(jailhouse_driver);
    return 0;
}

static int
jailhouseStateInitialize(bool privileged G_GNUC_UNUSED,
                         const char *root G_GNUC_UNUSED,
                         virStateInhibitCallback callback G_GNUC_UNUSED,
                         void *opaque G_GNUC_UNUSED)
{
    virJailhouseDriverConfigPtr cfg = NULL;
    int rc;

    jailhouse_driver = g_new0(virJailhouseDriver, 1);
    jailhouse_driver->lockFD = -1;

    if (virMutexInit(&jailhouse_driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        VIR_FREE(jailhouse_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (!(jailhouse_driver->domains = virDomainObjListNew()))
        goto error;

    if (!(cfg = virJailhouseDriverConfigNew()))
        goto error;

    jailhouse_driver->config = cfg;

    if (jailhouseLoadConf(cfg) < 0)
        goto error;

    if (virFileMakePath(cfg->stateDir) < 0) {
        virReportSystemError(errno, _("Failed to create state dir %s"),
                             cfg->stateDir);
        goto error;
    }

    if ((jailhouse_driver->lockFD = virPidFileAcquire(cfg->stateDir,
                                                      "driver", false, getpid())) < 0)
        goto error;

    if ((rc = jailhouseEnable(cfg->sys_config_file_path)) < 0)
        goto error;
    else if (rc == 0)
        return VIR_DRV_STATE_INIT_SKIPPED;

    if (jailhouseCreateAndLoadCells(jailhouse_driver) < 0)
        goto error;

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    jailhouseStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;

}
static const char *
jailhouseConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "JAILHOUSE";
}

static char *
jailhouseConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static int
jailhouseNodeGetInfo(virConnectPtr conn,
                     virNodeInfoPtr nodeinfo)
{
    UNUSED(conn);
    UNUSED(nodeinfo);
    return -1;
}

static int
jailhouseConnectListAllDomains(virConnectPtr conn,
                               virDomainPtr **domain, unsigned int flags)
{
    UNUSED(conn);
    UNUSED(domain);
    UNUSED(flags);
    return -1;
}

static virDomainPtr
jailhouseDomainLookupByID(virConnectPtr conn, int id)
{
    UNUSED(conn);
    UNUSED(id);
    return NULL;
}

static virDomainPtr
jailhouseDomainLookupByName(virConnectPtr conn, const char *name)
{
    UNUSED(conn);
    UNUSED(name);
    return NULL;
}

static virDomainPtr
jailhouseDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    UNUSED(conn);
    UNUSED(uuid);
    return NULL;
}

static virDomainObjPtr
virJailhouseDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr cell;
    virJailhouseDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    cell = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!cell) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return cell;
}



static virJailhouseCellInfoPtr
virJailhouseFindCellByName(virJailhouseDriverPtr driver,
                           char* name)
{
    virJailhouseCellInfoPtr *cell = driver->cell_info_list;

    while (*cell) {
        if (STRCASEEQ((*cell)->id.name, name))
            return *cell;
        cell++;
    }

    return NULL;
}

static int
jailhouseDomainCreateWithFlags(virDomainPtr domain,
                               unsigned int flags)
{
    virJailhouseDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr cell;
    virJailhouseCellInfoPtr cell_info;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_NONE, -1);

    if (!domain->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Error while reading the domain name"));
        goto cleanup;
    }

    if (!domain->id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Error while reading the domain ID"));
        goto cleanup;
    }

    if (!(cell = virJailhouseDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(domain->conn, cell->def) < 0)
        goto cleanup;

    if (!(cell_info = virJailhouseFindCellByName(driver, cell->def->name))) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name %s and ID %d)"),
                       cell->def->name, cell->def->id);
        virDomainObjListRemove(driver->domains, cell);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&cell);
    return ret;

}

static int
jailhouseDomainCreate(virDomainPtr domain)
{
    return jailhouseDomainCreateWithFlags(domain, 0);
}

static virDomainPtr
jailhouseDomainCreateXML(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags)
{
    virJailhouseDriverPtr driver = conn->privateData;
    virJailhouseCellInfoPtr cell_info;
    virDomainPtr dom = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr cell = NULL;
    virDomainDiskDefPtr disk = NULL;
    virJailhouseCellId cell_id;
    char **images = NULL;
    int num_images = 0, i = 0;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((def = virDomainDefParseString(xml, NULL,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if ((cell = virDomainObjListFindByUUID(driver->domains, def->uuid)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(cell_info = virJailhouseFindCellByName(driver, def->name))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("cell info for %s not found"),
                       def->name);
        goto cleanup;
    }

    // Assign cell Id to the domain.
    def->id = cell_info->id.id;

    if (!(cell = virDomainObjListAdd(driver->domains, def,
                                   NULL,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL)))
        goto cleanup;

    def = NULL;

    if (cell->def->ndisks < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain XML doesn't contain any disk images"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(images, cell->def->ndisks) < 0)
        goto cleanup;

    for (i = 0; i < cell->def->ndisks; ++i) {
        images[i] = NULL;

        if (cell->def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            virDomainDiskGetType(cell->def->disks[i]) == VIR_STORAGE_TYPE_FILE) {
            disk = cell->def->disks[i];
            const char *src = virDomainDiskGetSource(disk);
            if (!src) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("First file-based harddisk has no source"));
                goto cleanup;
            }

            images[i] = (char *)src;
            num_images++;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("A Jailhouse doamin(cell) can ONLY have FILE type disks"));
            goto cleanup;
        }
    }

    // Initialize the cell_id.
    cell_id.id = cell->def->id;
    cell_id.padding = 0;
    if (virStrncpy(cell_id.name, cell->def->name, JAILHOUSE_CELL_ID_NAMELEN, JAILHOUSE_CELL_ID_NAMELEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cell name %s length exceeded the limit"),
                       cell->def->name);
        goto cleanup;
    }

    if (loadImagesInCell(cell_id, images, num_images) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load images in the Cell %s"),
                       cell->def->name);
        goto cleanup;
    }

    VIR_DEBUG("Starting the domain...");

    if (startCell(cell_id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to start the Cell %s"),
                       cell->def->name);
        goto cleanup;
    }

    virDomainObjSetState(cell, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    dom = virGetDomain(conn, cell->def->name, cell->def->uuid, cell->def->id);

 cleanup:
    virDomainDefFree(def);
    virDomainObjEndAPI(&cell);
    return dom;
}

static int
jailhouseDomainShutdown(virDomainPtr domain)
{
    UNUSED(domain);
    return -1;
}

static int
jailhouseDomainDestroy(virDomainPtr domain)
{
    UNUSED(domain);
    return -1;
}

static int
jailhouseDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    UNUSED(domain);
    UNUSED(info);
    return -1;
}

static int
jailhouseDomainGetState(virDomainPtr domain,
                        int *state, int *reason, unsigned int flags)
{
    UNUSED(domain);
    UNUSED(state);
    UNUSED(reason);
    UNUSED(flags);
    return -1;
}

static char *
jailhouseDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    UNUSED(domain);
    UNUSED(flags);
    return NULL;
}

static virHypervisorDriver jailhouseHypervisorDriver = {
    .name = "JAILHOUSE",
    .connectOpen = jailhouseConnectOpen,        /* 6.3.0 */
    .connectClose = jailhouseConnectClose,      /* 6.3.0 */
    .connectListAllDomains = jailhouseConnectListAllDomains,    /* 6.3.0 */
    .connectGetType = jailhouseConnectGetType,  /* 6.3.0 */
    .connectGetHostname = jailhouseConnectGetHostname,  /* 6.3.0 */
    .domainCreate = jailhouseDomainCreate,       /*6.3.0 */
    .domainCreateWithFlags = jailhouseDomainCreateWithFlags,    /* 6.3.0 */
    .domainCreateXML = jailhouseDomainCreateXML, /* 6.3.0 */
    .domainShutdown = jailhouseDomainShutdown,  /* 6.3.0 */
    .domainDestroy = jailhouseDomainDestroy,    /* 6.3.0 */
    .domainGetInfo = jailhouseDomainGetInfo,    /* 6.3.0 */
    .domainGetState = jailhouseDomainGetState,  /* 6.3.0 */
    .domainLookupByID = jailhouseDomainLookupByID,      /* 6.3.0 */
    .domainLookupByUUID = jailhouseDomainLookupByUUID,  /* 6.3.0 */
    .domainLookupByName = jailhouseDomainLookupByName,  /* 6.3.0 */
    .domainGetXMLDesc = jailhouseDomainGetXMLDesc,      /* 6.3.0 */
    .nodeGetInfo = jailhouseNodeGetInfo,        /* 6.3.0 */
};


static virConnectDriver jailhouseConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "jailhouse", NULL },
    .hypervisorDriver = &jailhouseHypervisorDriver,
};


static virStateDriver jailhouseStateDriver = {
    .name = "JAILHOUSE",
    .stateInitialize = jailhouseStateInitialize,
    .stateCleanup = jailhouseStateCleanup,
};

int
jailhouseRegister(void)
{
    if (virRegisterConnectDriver(&jailhouseConnectDriver, false) < 0)
        return -1;
    if (virRegisterStateDriver(&jailhouseStateDriver) < 0)
        return -1;
    return 0;
}
