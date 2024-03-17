/*
 * node_device_driver.c: node device enumeration
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
 * Copyright (C) 2008 Virtual Iron Software, Inc.
 * Copyright (C) 2008 David F. Lively
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "virerror.h"
#include "datatypes.h"
#include "domain_addr.h"
#include "viralloc.h"
#include "virfile.h"
#include "virjson.h"
#include "node_device_conf.h"
#include "node_device_event.h"
#include "node_device_driver.h"
#if WITH_UDEV
# include "node_device_udev.h"
#endif
#include "virvhba.h"
#include "viraccessapicheck.h"
#include "virutil.h"
#include "vircommand.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("node_device.node_device_driver");

virNodeDeviceDriverState *driver;


VIR_ENUM_IMPL(virMdevctlCommand,
              MDEVCTL_CMD_LAST,
              "start", "stop", "define", "undefine", "create", "modify"
);


#define MDEVCTL_ERROR(msg) (msg && msg[0] != '\0' ? msg : _("Unknown error"))


virDrvOpenStatus
nodeConnectOpen(virConnectPtr conn,
                virConnectAuthPtr auth G_GNUC_UNUSED,
                virConf *conf G_GNUC_UNUSED,
                unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nodedev state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!virConnectValidateURIPath(conn->uri->path,
                                   "nodedev",
                                   driver->privileged))
        return VIR_DRV_OPEN_ERROR;

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

int nodeConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}


int nodeConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


int nodeConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


int nodeConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

#if defined (__linux__) && defined(WITH_UDEV)
/* NB: It was previously believed that changes in driver name were
 * relayed to libvirt as "change" events by udev, and the udev event
 * notification is setup to recognize such events and effectively
 * recreate the device entry in the cache. However, neither the kernel
 * nor udev sends such an event, so it is necessary to manually update
 * the driver name for a device each time its entry is used.
 */
static int
nodeDeviceUpdateDriverName(virNodeDeviceDef *def)
{
    g_autofree char *driver_link = NULL;
    g_autofree char *devpath = NULL;
    char *p;

    VIR_FREE(def->driver);

    driver_link = g_strdup_printf("%s/driver", def->sysfs_path);

    /* Some devices don't have an explicit driver, so just return
       without a name */
    if (access(driver_link, R_OK) < 0)
        return 0;

    if (virFileResolveLink(driver_link, &devpath) < 0) {
        virReportSystemError(errno,
                             _("cannot resolve driver link %1$s"), driver_link);
        return -1;
    }

    p = strrchr(devpath, '/');
    if (p)
        def->driver = g_strdup(p + 1);

    return 0;
}
#else
/* XXX: Implement me for non-linux */
static int
nodeDeviceUpdateDriverName(virNodeDeviceDef *def G_GNUC_UNUSED)
{
    return 0;
}
#endif


static int
nodeDeviceInitWait(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    while (!driver->initialized) {
        if (virCondWait(&driver->initCond, &driver->lock) < 0) {
            virReportSystemError(errno, "%s", _("failed to wait on condition"));
            return -1;
        }
    }

    return 0;
}

int
nodeNumOfDevices(virConnectPtr conn,
                 const char *cap,
                 unsigned int flags)
{
    if (virNodeNumOfDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    if (nodeDeviceInitWait() < 0)
        return -1;

    return virNodeDeviceObjListNumOfDevices(driver->devs, conn, cap,
                                            virNodeNumOfDevicesCheckACL);
}


int
nodeListDevices(virConnectPtr conn,
                const char *cap,
                char **const names,
                int maxnames,
                unsigned int flags)
{
    if (virNodeListDevicesEnsureACL(conn) < 0)
        return -1;

    virCheckFlags(0, -1);

    if (nodeDeviceInitWait() < 0)
        return -1;

    return virNodeDeviceObjListGetNames(driver->devs, conn,
                                        virNodeListDevicesCheckACL,
                                        cap, names, maxnames);
}


int
nodeConnectListAllNodeDevices(virConnectPtr conn,
                              virNodeDevicePtr **devices,
                              unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_ALL, -1);

    if (virConnectListAllNodeDevicesEnsureACL(conn) < 0)
        return -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    return virNodeDeviceObjListExport(conn, driver->devs, devices,
                                      virConnectListAllNodeDevicesCheckACL,
                                      flags);
}


static virNodeDeviceObj *
nodeDeviceObjFindByName(const char *name)
{
    virNodeDeviceObj *obj;

    if (!(obj = virNodeDeviceObjListFindByName(driver->devs, name))) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%1$s'"),
                       name);
    }

    return obj;
}


virNodeDevicePtr
nodeDeviceLookupByName(virConnectPtr conn,
                       const char *name)
{
    virNodeDeviceObj *obj;
    virNodeDeviceDef *def;
    virNodeDevicePtr device = NULL;

    if (nodeDeviceInitWait() < 0)
        return NULL;

    if (!(obj = nodeDeviceObjFindByName(name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    if ((device = virGetNodeDevice(conn, name)))
        device->parentName = g_strdup(def->parent);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return device;
}


virNodeDevicePtr
nodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                              const char *wwnn,
                              const char *wwpn,
                              unsigned int flags)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;
    virNodeDevicePtr device = NULL;

    virCheckFlags(0, NULL);

    if (nodeDeviceInitWait() < 0)
        return NULL;

    if (!(obj = virNodeDeviceObjListFindSCSIHostByWWNs(driver->devs,
                                                       wwnn, wwpn)))
        return NULL;

    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceLookupSCSIHostByWWNEnsureACL(conn, def) < 0)
        goto cleanup;

    if ((device = virGetNodeDevice(conn, def->name)))
        device->parentName = g_strdup(def->parent);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return device;
}

static virNodeDevicePtr
nodeDeviceLookupMediatedDeviceByUUID(virConnectPtr conn,
                                     const char *uuid,
                                     const char *parent_addr,
                                     unsigned int flags)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;
    virNodeDevicePtr device = NULL;

    virCheckFlags(0, NULL);

    if (!(obj = virNodeDeviceObjListFindMediatedDeviceByUUID(driver->devs,
                                                             uuid, parent_addr)))
        return NULL;

    def = virNodeDeviceObjGetDef(obj);

    if ((device = virGetNodeDevice(conn, def->name)))
        device->parentName = g_strdup(def->parent);

    virNodeDeviceObjEndAPI(&obj);
    return device;
}


char *
nodeDeviceGetXMLDesc(virNodeDevicePtr device,
                     unsigned int flags)
{
    virNodeDeviceObj *obj;
    virNodeDeviceDef *def;
    char *ret = NULL;

    virCheckFlags(VIR_NODE_DEVICE_XML_INACTIVE, NULL);

    if (nodeDeviceInitWait() < 0)
        return NULL;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceGetXMLDescEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (nodeDeviceUpdateDriverName(def) < 0)
        goto cleanup;

    if (virNodeDeviceUpdateCaps(def) < 0)
        goto cleanup;

    if (flags & VIR_NODE_DEVICE_XML_INACTIVE) {
        if (!virNodeDeviceObjIsPersistent(obj)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("node device '%1$s' is not persistent"),
                           def->name);
            goto cleanup;
        }
    } else {
        if (!virNodeDeviceObjIsActive(obj))
            flags |= VIR_NODE_DEVICE_XML_INACTIVE;
    }

    ret = virNodeDeviceDefFormat(def, flags);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


char *
nodeDeviceGetParent(virNodeDevicePtr device)
{
    virNodeDeviceObj *obj;
    virNodeDeviceDef *def;
    char *ret = NULL;

    if (nodeDeviceInitWait() < 0)
        return NULL;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return NULL;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceGetParentEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (def->parent) {
        ret = g_strdup(def->parent);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no parent for this device"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeDeviceNumOfCaps(virNodeDevicePtr device)
{
    virNodeDeviceObj *obj;
    virNodeDeviceDef *def;
    int ret = -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceNumOfCapsEnsureACL(device->conn, def) < 0)
        goto cleanup;

    ret = virNodeDeviceCapsListExport(def, NULL);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}



int
nodeDeviceListCaps(virNodeDevicePtr device,
                   char **const names,
                   int maxnames)
{
    virNodeDeviceObj *obj;
    virNodeDeviceDef *def;
    g_autofree virNodeDevCapType *list = NULL;
    int ncaps = 0;
    int ret = -1;
    size_t i = 0;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceListCapsEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if ((ncaps = virNodeDeviceCapsListExport(def, &list)) < 0)
        goto cleanup;

    if (ncaps > maxnames)
        ncaps = maxnames;

    for (i = 0; i < ncaps; i++)
        names[i] = g_strdup(virNodeDevCapTypeToString(list[i]));

    ret = ncaps;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    if (ret < 0) {
        size_t j;
        for (j = 0; j < i; j++)
            VIR_FREE(names[j]);
    }
    return ret;
}


static int
nodeDeviceGetTime(time_t *t)
{
    int ret = 0;

    *t = time(NULL);
    if (*t == (time_t)-1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Could not get current time"));

        *t = 0;
        ret = -1;
    }

    return ret;
}


typedef virNodeDevicePtr (*nodeDeviceFindNewDeviceFunc)(virConnectPtr conn,
                                                        const void* opaque);


/* When large numbers of devices are present on the host, it's
 * possible for udev not to realize that it has work to do before we
 * get here.  We thus keep trying to find the new device we just
 * created for up to LINUX_NEW_DEVICE_WAIT_TIME.  Note that udev's
 * default settle time is 180 seconds, so once udev realizes that it
 * has work to do, it might take that long for the udev wait to
 * return.  Thus the total maximum time for this function to return is
 * the udev settle time plus LINUX_NEW_DEVICE_WAIT_TIME.
 *
 * This whole area is a race, but if we retry the udev wait for
 * LINUX_NEW_DEVICE_WAIT_TIME seconds and there's still no device,
 * it's probably safe to assume it's not going to appear.
 */
static virNodeDevicePtr
nodeDeviceFindNewDevice(virConnectPtr conn,
                        nodeDeviceFindNewDeviceFunc func,
                        const void *opaque)
{
    virNodeDevicePtr device = NULL;
    time_t start = 0, now = 0;

    nodeDeviceGetTime(&start);

    while ((now - start) < LINUX_NEW_DEVICE_WAIT_TIME) {

        virWaitForDevices();

        device = func(conn, opaque);

        if (device != NULL)
            break;

        sleep(5);
        if (nodeDeviceGetTime(&now) == -1)
            break;
    }

    return device;
}


typedef struct {
    const char *uuid;
    const char *parent_addr;
} NewMediatedDeviceData;

static virNodeDevicePtr
nodeDeviceFindNewMediatedDeviceFunc(virConnectPtr conn,
                                    const void *opaque)
{
    const NewMediatedDeviceData *data = opaque;

    return nodeDeviceLookupMediatedDeviceByUUID(conn, data->uuid, data->parent_addr, 0);
}


static virNodeDevicePtr
nodeDeviceFindNewMediatedDevice(virConnectPtr conn,
                                const char *mdev_uuid,
                                const char *parent_addr)
{
    NewMediatedDeviceData data = {mdev_uuid, parent_addr};
    return nodeDeviceFindNewDevice(conn, nodeDeviceFindNewMediatedDeviceFunc,
                                   &data);
}


typedef struct _NewSCSIHostFuncData NewSCSIHostFuncData;
struct _NewSCSIHostFuncData
{
    const char *wwnn;
    const char *wwpn;
};


static virNodeDevicePtr
nodeDeviceFindNewSCSIHostFunc(virConnectPtr conn,
                              const void *opaque)
{
    const NewSCSIHostFuncData *data = opaque;

    return nodeDeviceLookupSCSIHostByWWN(conn, data->wwnn, data->wwpn, 0);
}


static virNodeDevicePtr
nodeDeviceFindNewSCSIHost(virConnectPtr conn,
                          const char *wwnn,
                          const char *wwpn)
{
    NewSCSIHostFuncData data = { .wwnn = wwnn, .wwpn = wwpn};

    return nodeDeviceFindNewDevice(conn, nodeDeviceFindNewSCSIHostFunc, &data);
}


static bool
nodeDeviceHasCapability(virNodeDeviceDef *def, virNodeDevCapType type)
{
    virNodeDevCapsDef *cap = def->caps;

    while (cap != NULL) {
        if (cap->data.type == type)
            return true;
        cap = cap->next;
    }

    return false;
}


static int
nodeDeviceAttributesToJSON(virJSONValue *json,
                           virMediatedDeviceConfig *config)
{
    size_t i;
    if (config->attributes) {
        g_autoptr(virJSONValue) attributes = virJSONValueNewArray();

        for (i = 0; i < config->nattributes; i++) {
            virMediatedDeviceAttr *attr = config->attributes[i];
            g_autoptr(virJSONValue) jsonattr = virJSONValueNewObject();

            if (virJSONValueObjectAppendString(jsonattr, attr->name, attr->value) < 0)
                return -1;

            if (virJSONValueArrayAppend(attributes, &jsonattr) < 0)
                return -1;
        }

        if (virJSONValueObjectAppend(json, "attrs", &attributes) < 0)
            return -1;
    }

    return 0;
}


/* format a json string that provides configuration information about this mdev
 * to the mdevctl utility */
static int
nodeDeviceDefToMdevctlConfig(virNodeDeviceDef *def, char **buf, bool defined)
{
    virNodeDevCapMdev *mdev = &def->caps->data.mdev;
    virMediatedDeviceConfig *mdev_config = defined ? &mdev->defined_config : &mdev->active_config;
    g_autoptr(virJSONValue) json = virJSONValueNewObject();
    const char *startval = mdev->autostart ? "auto" : "manual";

    if (virJSONValueObjectAppendString(json, "mdev_type", mdev_config->type) < 0)
        return -1;

    if (virJSONValueObjectAppendString(json, "start", startval) < 0)
        return -1;

    if (nodeDeviceAttributesToJSON(json, mdev_config) < 0)
        return -1;

    *buf = virJSONValueToString(json, false);
    if (!*buf)
        return -1;

    return 0;
}


static char *
nodeDeviceObjFormatAddress(virNodeDeviceObj *obj)
{
    virNodeDevCapsDef *caps = NULL;
    char *addr = NULL;
    virNodeDeviceDef *def = virNodeDeviceObjGetDef(obj);
    for (caps = def->caps; caps != NULL; caps = caps->next) {
        switch (caps->data.type) {
        case VIR_NODE_DEV_CAP_PCI_DEV: {
            virPCIDeviceAddress pci_addr = {
                .domain = caps->data.pci_dev.domain,
                .bus = caps->data.pci_dev.bus,
                .slot = caps->data.pci_dev.slot,
                .function = caps->data.pci_dev.function
            };

            addr = virPCIDeviceAddressAsString(&pci_addr);
            break;
            }

        case VIR_NODE_DEV_CAP_CSS_DEV: {
            virCCWDeviceAddress ccw_addr = {
                .cssid = caps->data.ccw_dev.cssid,
                .ssid = caps->data.ccw_dev.ssid,
                .devno = caps->data.ccw_dev.devno
            };

            addr = virCCWDeviceAddressAsString(&ccw_addr);
            break;
            }

        case VIR_NODE_DEV_CAP_AP_MATRIX:
            addr = g_strdup(caps->data.ap_matrix.addr);
            break;

        case VIR_NODE_DEV_CAP_MDEV_TYPES:
            addr = g_strdup(caps->data.mdev_parent.address);
            break;

        case VIR_NODE_DEV_CAP_SYSTEM:
        case VIR_NODE_DEV_CAP_USB_DEV:
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
        case VIR_NODE_DEV_CAP_NET:
        case VIR_NODE_DEV_CAP_SCSI_HOST:
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
        case VIR_NODE_DEV_CAP_SCSI:
        case VIR_NODE_DEV_CAP_STORAGE:
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        case VIR_NODE_DEV_CAP_DRM:
        case VIR_NODE_DEV_CAP_MDEV:
        case VIR_NODE_DEV_CAP_CCW_DEV:
        case VIR_NODE_DEV_CAP_VDPA:
        case VIR_NODE_DEV_CAP_AP_CARD:
        case VIR_NODE_DEV_CAP_AP_QUEUE:
        case VIR_NODE_DEV_CAP_VPD:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }

        if (addr)
            break;
    }

    return addr;
}


virCommand *
nodeDeviceGetMdevctlCommand(virNodeDeviceDef *def,
                            virMdevctlCommand cmd_type,
                            char **outbuf,
                            char **errbuf)
{
    g_autoptr(virCommand) cmd = NULL;
    const char *subcommand = virMdevctlCommandTypeToString(cmd_type);
    g_autofree char *inbuf = NULL;

    switch (cmd_type) {
    case MDEVCTL_CMD_CREATE:
        /* now is the time to make sure "create" is replaced with "start" on
         * mdevctl cmdline */
        cmd = virCommandNewArgList(MDEVCTL, "start", NULL);
        break;
    case MDEVCTL_CMD_STOP:
    case MDEVCTL_CMD_START:
    case MDEVCTL_CMD_DEFINE:
    case MDEVCTL_CMD_UNDEFINE:
    case MDEVCTL_CMD_MODIFY:
        cmd = virCommandNewArgList(MDEVCTL, subcommand, NULL);
        break;
    case MDEVCTL_CMD_LAST:
    default:
        /* SHOULD NEVER HAPPEN */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown Command '%1$i'"), cmd_type);
        return NULL;
    }

    switch (cmd_type) {
    case MDEVCTL_CMD_CREATE:
    case MDEVCTL_CMD_DEFINE:
    case MDEVCTL_CMD_MODIFY:
        if (!def->caps->data.mdev.parent_addr) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to find parent device '%1$s'"), def->parent);
            return NULL;
        }

        if (nodeDeviceDefToMdevctlConfig(def, &inbuf, true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("couldn't convert node device def to mdevctl JSON"));
            return NULL;
        }

        virCommandAddArgPair(cmd, "--parent", def->caps->data.mdev.parent_addr);
        virCommandAddArgPair(cmd, "--jsonfile", "/dev/stdin");

        virCommandSetInputBuffer(cmd, inbuf);
        if (outbuf)
            virCommandSetOutputBuffer(cmd, outbuf);
        break;

    case MDEVCTL_CMD_UNDEFINE:
    case MDEVCTL_CMD_STOP:
    case MDEVCTL_CMD_START:
        /* No special handling here, we only need to pass UUID with these */
        break;
    case MDEVCTL_CMD_LAST:
    default:
        /* SHOULD NEVER HAPPEN */
        break;
    }

    /* Fill in UUID for commands that need it */
    if (def->caps->data.mdev.uuid)
        virCommandAddArgPair(cmd, "--uuid", def->caps->data.mdev.uuid);

    virCommandSetErrorBuffer(cmd, errbuf);

    return g_steal_pointer(&cmd);
}


static int
virMdevctlCreate(virNodeDeviceDef *def, char **uuid)
{
    int status;
    g_autofree char *errmsg = NULL;
    g_autoptr(virCommand) cmd = nodeDeviceGetMdevctlCommand(def,
                                                            MDEVCTL_CMD_CREATE,
                                                            uuid,
                                                            &errmsg);

    if (!cmd)
        return -1;

    /* an auto-generated uuid is returned via stdout if no uuid is specified in
     * the mdevctl args */
    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to start mediated device: %1$s"),
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    /* remove newline */
    *uuid = g_strstrip(*uuid);
    return 0;
}


static int
virMdevctlDefine(virNodeDeviceDef *def, char **uuid)
{
    int status;
    g_autofree char *errmsg = NULL;
    g_autoptr(virCommand) cmd = nodeDeviceGetMdevctlCommand(def,
                                                            MDEVCTL_CMD_DEFINE,
                                                            uuid, &errmsg);

    if (!cmd)
        return -1;

    /* an auto-generated uuid is returned via stdout if no uuid is specified in
     * the mdevctl args */
    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to define mediated device: %1$s"),
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    /* remove newline */
    *uuid = g_strstrip(*uuid);
    return 0;
}


/* gets a virCommand object that executes a mdevctl command to modify a
 * a device to an updated version
 */
virCommand*
nodeDeviceGetMdevctlModifyCommand(virNodeDeviceDef *def,
                                  bool defined,
                                  bool live,
                                  char **errmsg)
{
    virCommand *cmd = nodeDeviceGetMdevctlCommand(def,
                                                  MDEVCTL_CMD_MODIFY,
                                                  NULL, errmsg);

    if (!cmd)
        return NULL;

    if (defined)
        virCommandAddArg(cmd, "--defined");

    if (live)
        virCommandAddArg(cmd, "--live");

    return cmd;
}


/* checks if mdevctl supports on the command modify the options live, defined
 * and jsonfile
 */
static int
nodeDeviceGetMdevctlModifySupportCheck(void)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;
    const char *subcommand = virMdevctlCommandTypeToString(MDEVCTL_CMD_MODIFY);

    cmd = virCommandNewArgList(MDEVCTL,
                               subcommand,
                               "--defined",
                               "--live",
                               "--jsonfile",
                               "b",
                               "--help",
                               NULL);

    if (!cmd)
        return -1;

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        /* update is unsupported */
        return -1;
    }

    return 0;
}


static int
virMdevctlModify(virNodeDeviceDef *def,
                 bool defined,
                 bool live)
{
    int status;
    g_autofree char *errmsg = NULL;
    g_autoptr(virCommand) cmd = nodeDeviceGetMdevctlModifyCommand(def,
                                                                  defined,
                                                                  live,
                                                                  &errmsg);

    if (!cmd)
        return -1;

    if (nodeDeviceGetMdevctlModifySupportCheck() < 0) {
        VIR_WARN("Installed mdevctl version does not support modify with options jsonfile, defined and live");
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to modify mediated device: modify unsupported"));
        return -1;
    }

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to modify mediated device: %1$s"),
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    return 0;
}


static virNodeDevicePtr
nodeDeviceCreateXMLMdev(virConnectPtr conn,
                        virNodeDeviceDef *def)
{
    g_autofree char *uuid = NULL;

    if (!def->parent) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("cannot create a mediated device without a parent"));
        return NULL;
    }

    if (virMdevctlCreate(def, &uuid) < 0) {
        return NULL;
    }

    if (uuid && uuid[0]) {
        g_free(def->caps->data.mdev.uuid);
        def->caps->data.mdev.uuid = g_steal_pointer(&uuid);
    }

    return nodeDeviceFindNewMediatedDevice(conn, def->caps->data.mdev.uuid,
                                           def->caps->data.mdev.parent_addr);
}


virNodeDevicePtr
nodeDeviceCreateXML(virConnectPtr conn,
                    const char *xmlDesc,
                    unsigned int flags)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    g_autofree char *wwnn = NULL;
    g_autofree char *wwpn = NULL;
    virNodeDevicePtr device = NULL;
    const char *virt_type = NULL;
    bool validate = flags & VIR_NODE_DEVICE_CREATE_XML_VALIDATE;

    virCheckFlags(VIR_NODE_DEVICE_CREATE_XML_VALIDATE, NULL);

    if (nodeDeviceInitWait() < 0)
        return NULL;

    virt_type  = virConnectGetType(conn);

    if (!(def = virNodeDeviceDefParse(xmlDesc, NULL, CREATE_DEVICE, virt_type,
                                      &driver->parserCallbacks, NULL, validate)))
        return NULL;

    if (virNodeDeviceCreateXMLEnsureACL(conn, def) < 0)
        return NULL;

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_SCSI_HOST)) {
        int parent_host;

        if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) == -1)
            return NULL;

        if ((parent_host = virNodeDeviceObjListGetParentHost(driver->devs, def)) < 0)
            return NULL;

        if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_CREATE) < 0)
            return NULL;

        device = nodeDeviceFindNewSCSIHost(conn, wwnn, wwpn);
        /* We don't check the return value, because one way or another,
         * we're returning what we get... */

        if (device == NULL)
            virReportError(VIR_ERR_NO_NODE_DEVICE,
                           _("no node device for '%1$s' with matching wwnn '%2$s' and wwpn '%3$s'"),
                           def->name, wwnn, wwpn);
    } else if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        device = nodeDeviceCreateXMLMdev(conn, def);
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
    }

    return device;
}


static int
virMdevctlStop(virNodeDeviceDef *def)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errmsg = NULL;

    cmd = nodeDeviceGetMdevctlCommand(def, MDEVCTL_CMD_STOP, NULL, &errmsg);

    if (!cmd)
        return -1;

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to destroy '%1$s': %2$s"), def->name,
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    return 0;
}


static int
virMdevctlUndefine(virNodeDeviceDef *def)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errmsg = NULL;

    cmd = nodeDeviceGetMdevctlCommand(def, MDEVCTL_CMD_UNDEFINE, NULL, &errmsg);

    if (!cmd)
        return -1;

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to undefine mediated device: %1$s"),
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    return 0;
}


static int
virMdevctlStart(virNodeDeviceDef *def)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errmsg = NULL;

    cmd = nodeDeviceGetMdevctlCommand(def, MDEVCTL_CMD_START, NULL, &errmsg);

    if (!cmd)
        return -1;

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to create mediated device: %1$s"),
                       MDEVCTL_ERROR(errmsg));
        return -1;
    }

    return 0;
}


/* gets a virCommand object that executes a mdevctl command to set the
 * 'autostart' property of the device to the specified value
 */
virCommand*
nodeDeviceGetMdevctlSetAutostartCommand(virNodeDeviceDef *def,
                                        bool autostart,
                                        char **errmsg)
{
    virCommand *cmd = virCommandNewArgList(MDEVCTL,
                                           "modify",
                                           "--uuid",
                                           def->caps->data.mdev.uuid,
                                           NULL);

    if (autostart)
        virCommandAddArg(cmd, "--auto");
    else
        virCommandAddArg(cmd, "--manual");

    virCommandSetErrorBuffer(cmd, errmsg);

    return cmd;
}


static int
virMdevctlSetAutostart(virNodeDeviceDef *def, bool autostart, char **errmsg)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;

    cmd = nodeDeviceGetMdevctlSetAutostartCommand(def, autostart, errmsg);

    if (virCommandRun(cmd, &status) < 0 || status != 0)
        return -1;

    return 0;
}


/**
 * nodeDeviceGetMdevctlListCommand:
 * @defined: list mdevctl entries with persistent config
 * @output: filled with the output of mdevctl once invoked
 * @errmsg: always allocated, optionally filled with error from 'mdevctl'
 *
 * Prepares a virCommand structure to invoke 'mdevctl' caller is responsible to
 * free the buffers which are filled by the virCommand infrastructure.
 */
virCommand*
nodeDeviceGetMdevctlListCommand(bool defined,
                                char **output,
                                char **errmsg)
{
    virCommand *cmd = virCommandNewArgList(MDEVCTL,
                                           "list",
                                           "--dumpjson",
                                           NULL);

    if (defined)
        virCommandAddArg(cmd, "--defined");

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, errmsg);

    return cmd;
}


static void mdevGenerateDeviceName(virNodeDeviceDef *dev)
{
    nodeDeviceGenerateName(dev, "mdev", dev->caps->data.mdev.uuid,
                           dev->caps->data.mdev.parent_addr);
}


static bool
matchDeviceAddress(virNodeDeviceObj *obj,
                   const void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);
    g_autofree char *addr = nodeDeviceObjFormatAddress(obj);

    return STREQ_NULLABLE(addr, opaque);
}


static int
nodeDeviceParseMdevctlAttributes(virMediatedDeviceConfig *config,
                                 virJSONValue *attrs)
{
    size_t i;

    if (attrs && virJSONValueIsArray(attrs)) {
        int nattrs = virJSONValueArraySize(attrs);

        config->attributes = g_new0(virMediatedDeviceAttr*, nattrs);
        config->nattributes = nattrs;

        for (i = 0; i < nattrs; i++) {
            virJSONValue *attr = virJSONValueArrayGet(attrs, i);
            virMediatedDeviceAttr *attribute;
            virJSONValue *value;

            if (!virJSONValueIsObject(attr) ||
                virJSONValueObjectKeysNumber(attr) != 1) {
                return -1;
            }

            attribute = g_new0(virMediatedDeviceAttr, 1);
            attribute->name = g_strdup(virJSONValueObjectGetKey(attr, 0));
            value = virJSONValueObjectGetValue(attr, 0);
            attribute->value = g_strdup(virJSONValueGetString(value));
            config->attributes[i] = attribute;
        }
    }

    return 0;
}


static virNodeDeviceDef*
nodeDeviceParseMdevctlChildDevice(const char *parent,
                                  virJSONValue *json,
                                  bool defined)
{
    virNodeDevCapMdev *mdev;
    virMediatedDeviceConfig *mdev_config;
    const char *uuid;
    virJSONValue *props;
    g_autoptr(virNodeDeviceDef) child = g_new0(virNodeDeviceDef, 1);
    virNodeDeviceObj *parent_obj;
    const char *start = NULL;

    /* the child object should have a single key equal to its uuid.
     * The value is an object describing the properties of the mdev */
    if (virJSONValueObjectKeysNumber(json) != 1)
        return NULL;

    uuid = virJSONValueObjectGetKey(json, 0);
    props = virJSONValueObjectGetValue(json, 0);

    /* Look up id of parent device. mdevctl supports defining mdevs for parent
     * devices that are not present on the system (to support starting mdevs on
     * hotplug, etc) so the parent may not actually exist. */
    if ((parent_obj = virNodeDeviceObjListFind(driver->devs, matchDeviceAddress,
                                               (void *)parent))) {
        virNodeDeviceDef *parentdef = virNodeDeviceObjGetDef(parent_obj);
        child->parent = g_strdup(parentdef->name);
        virNodeDeviceObjEndAPI(&parent_obj);
    };
    if (!child->parent)
        child->parent = g_strdup("computer");
    child->caps = g_new0(virNodeDevCapsDef, 1);
    child->caps->data.type = VIR_NODE_DEV_CAP_MDEV;

    mdev = &child->caps->data.mdev;
    mdev_config = defined ? &mdev->defined_config : &mdev->active_config;
    mdev->uuid = g_strdup(uuid);
    mdev->parent_addr = g_strdup(parent);
    mdev_config->type =
        g_strdup(virJSONValueObjectGetString(props, "mdev_type"));
    start = virJSONValueObjectGetString(props, "start");
    mdev->autostart = STREQ_NULLABLE(start, "auto");

    if (nodeDeviceParseMdevctlAttributes(mdev_config,
                                         virJSONValueObjectGet(props, "attrs")) < 0)
        return NULL;

    mdevGenerateDeviceName(child);

    return g_steal_pointer(&child);
}


int
nodeDeviceParseMdevctlJSON(const char *jsonstring,
                           virNodeDeviceDef ***devs,
                           bool defined)
{
    int n;
    g_autoptr(virJSONValue) json_devicelist = NULL;
    virNodeDeviceDef **outdevs = NULL;
    size_t noutdevs = 0;
    size_t i;
    size_t j;
    virJSONValue *obj;

    if (virStringIsEmpty(jsonstring)) {
        VIR_DEBUG("mdevctl has no defined mediated devices");
        *devs = NULL;
        return 0;
    }

    json_devicelist = virJSONValueFromString(jsonstring);

    if (!json_devicelist || !virJSONValueIsArray(json_devicelist)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("mdevctl JSON response contains no devices"));
        goto error;
    }

    if (virJSONValueArraySize(json_devicelist) == 0) {
        VIR_DEBUG("mdevctl has no defined mediated devices");
        *devs = NULL;
        return 0;
    }

    /* mdevctl list --dumpjson produces an output that is an array that
     * contains only a single object which contains a property for each parent
     * device */
    if (virJSONValueArraySize(json_devicelist) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected format for mdevctl response"));
        goto error;
    }

    obj = virJSONValueArrayGet(json_devicelist, 0);

    if (!virJSONValueIsObject(obj)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("device list is not an object"));
        goto error;
    }

    n = virJSONValueObjectKeysNumber(obj);
    for (i = 0; i < n; i++) {
        const char *parent;
        virJSONValue *child_array;
        int nchildren;

        /* The key of each object property is the name of a parent device
         * which maps to an array of child devices */
        parent = virJSONValueObjectGetKey(obj, i);
        child_array = virJSONValueObjectGetValue(obj, i);

        if (!virJSONValueIsArray(child_array)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Parent device's JSON object data is not an array"));
            goto error;
        }

        nchildren = virJSONValueArraySize(child_array);

        for (j = 0; j < nchildren; j++) {
            g_autoptr(virNodeDeviceDef) child = NULL;
            virJSONValue *child_obj = virJSONValueArrayGet(child_array, j);

            if (!(child = nodeDeviceParseMdevctlChildDevice(parent, child_obj, defined))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to parse child device"));
                goto error;
            }

            VIR_APPEND_ELEMENT(outdevs, noutdevs, child);
        }
    }

    *devs = outdevs;
    return noutdevs;

 error:
    for (i = 0; i < noutdevs; i++)
        virNodeDeviceDefFree(outdevs[i]);
    VIR_FREE(outdevs);
    return -1;
}


int
nodeDeviceDestroy(virNodeDevicePtr device)
{
    int ret = -1;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;
    g_autofree char *parent = NULL;
    g_autofree char *wwnn = NULL;
    g_autofree char *wwpn = NULL;
    unsigned int parent_host;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceDestroyEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_SCSI_HOST)) {
        if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) < 0)
            goto cleanup;

        /* Because we're about to release the lock and thus run into a race
         * possibility (however improbable) with a udevAddOneDevice change
         * event which would essentially free the existing @def (obj->def) and
         * replace it with something new, we need to grab the parent field
         * and then find the parent obj in order to manage the vport */
        parent = g_strdup(def->parent);

        virNodeDeviceObjEndAPI(&obj);

        if (!(obj = virNodeDeviceObjListFindByName(driver->devs, parent))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot find parent '%1$s' definition"), parent);
            goto cleanup;
        }

        if (virSCSIHostGetNumber(parent, &parent_host) < 0)
            goto cleanup;

        if (virVHBAManageVport(parent_host, wwpn, wwnn, VPORT_DELETE) < 0)
            goto cleanup;

        ret = 0;
    } else if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        g_autofree char *vfiogroup = NULL;
        VIR_AUTOCLOSE fd = -1;

        if (!virNodeDeviceObjIsActive(obj)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Device '%1$s' is not active"), def->name);
            goto cleanup;
        }

        /* If this mediated device is in use by a vm, attempting to stop it
         * will block until the vm closes the device. The nodedev driver
         * cannot query the hypervisor driver to determine whether the device
         * is in use by any active domains, since that would introduce circular
         * dependencies between daemons and add a risk of deadlocks. So we need
         * to resort to a workaround.  vfio only allows the group for a device
         * to be opened by one user at a time. So if we get EBUSY when opening
         * the group, we infer that the device is in use and therefore we
         * shouldn't try to remove the device. */
        vfiogroup = virMediatedDeviceGetIOMMUGroupDev(def->caps->data.mdev.uuid);
        if (!vfiogroup)
            goto cleanup;

        fd = open(vfiogroup, O_RDONLY);

        if (fd < 0 && errno == EBUSY) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to destroy '%1$s': device in use"),
                           def->name);
            goto cleanup;
        }

        if (virMdevctlStop(def) < 0)
            goto cleanup;

        ret = 0;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


/* takes ownership of @def and potentially frees it. @def should not be used
 * after returning from this function */
static int
nodeDeviceUpdateMediatedDevice(virNodeDeviceDef *def,
                               bool defined)
{
    virNodeDeviceObj *obj;
    virObjectEvent *event;
    bool was_defined = false;
    g_autoptr(virNodeDeviceDef) owned = def;
    g_autofree char *name = g_strdup(owned->name);

    owned->driver = g_strdup("vfio_mdev");

    if (!(obj = virNodeDeviceObjListFindByName(driver->devs, owned->name))) {
        virNodeDeviceDef *d = g_steal_pointer(&owned);
        if (!(obj = virNodeDeviceObjListAssignDef(driver->devs, d))) {
            virNodeDeviceDefFree(d);
            return -1;
        }
    } else {
        bool changed;
        virNodeDeviceDef *olddef = virNodeDeviceObjGetDef(obj);

        was_defined = virNodeDeviceObjIsPersistent(obj);
        /* Active devices contain some additional information (e.g. sysfs
         * path) that is not provided by mdevctl, so re-use the existing
         * definition and copy over new mdev data */
        changed = nodeDeviceDefCopyFromMdevctl(olddef, owned, defined);

        if (was_defined && !changed) {
            /* if this device was already defined and the definition
             * hasn't changed, there's nothing to do for this device */
            virNodeDeviceObjEndAPI(&obj);
            return 0;
        }
    }

    if (defined)
        virNodeDeviceObjSetPersistent(obj, true);
    virNodeDeviceObjSetAutostart(obj, def->caps->data.mdev.autostart);

    if (!was_defined && defined)
        event = virNodeDeviceEventLifecycleNew(name,
                                               VIR_NODE_DEVICE_EVENT_DEFINED,
                                               0);
    else
        event = virNodeDeviceEventUpdateNew(name);

    virNodeDeviceObjEndAPI(&obj);
    virObjectEventStateQueue(driver->nodeDeviceEventState, event);

    return 0;
}


static virNodeDeviceObj*
findPersistentMdevNodeDevice(virNodeDeviceDef *def)
{
    virNodeDeviceObj *obj = NULL;

    if (!nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV))
        return NULL;

    if (def->caps->data.mdev.uuid &&
        def->caps->data.mdev.parent_addr &&
        (obj = virNodeDeviceObjListFindMediatedDeviceByUUID(driver->devs,
                                                            def->caps->data.mdev.uuid,
                                                            def->caps->data.mdev.parent_addr)) &&
        !virNodeDeviceObjIsPersistent(obj)) {
        virNodeDeviceObjEndAPI(&obj);
    }

    return obj;
}


virNodeDevice*
nodeDeviceDefineXML(virConnect *conn,
                    const char *xmlDesc,
                    unsigned int flags)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    virNodeDeviceObj *persistent_obj = NULL;
    const char *virt_type = NULL;
    g_autofree char *uuid = NULL;
    g_autofree char *name = NULL;
    bool validate = flags & VIR_NODE_DEVICE_DEFINE_XML_VALIDATE;
    bool modify_failed = false;

    virCheckFlags(VIR_NODE_DEVICE_DEFINE_XML_VALIDATE, NULL);

    if (nodeDeviceInitWait() < 0)
        return NULL;

    virt_type  = virConnectGetType(conn);

    if (!(def = virNodeDeviceDefParse(xmlDesc, NULL, CREATE_DEVICE, virt_type,
                                      &driver->parserCallbacks, NULL, validate)))
        return NULL;

    if (virNodeDeviceDefineXMLEnsureACL(conn, def) < 0)
        return NULL;

    if (!nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
        return NULL;
    }

    if (!def->parent) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("cannot define a mediated device without a parent"));
        return NULL;
    }

    if ((persistent_obj = findPersistentMdevNodeDevice(def))) {
        /* virNodeDeviceObjUpdateModificationImpact() is not required we
         * will modify the persistent config only.
         * nodeDeviceDefValidateUpdate() is not required as uuid and
         * parent are matching if def was found and changing the type in
         * the persistent config is allowed. */
        VIR_DEBUG("Update node device '%s' with mdevctl", def->name);
        modify_failed = (virMdevctlModify(def, true, false) < 0);
        virNodeDeviceObjEndAPI(&persistent_obj);
        if (modify_failed)
            return NULL;
    } else {
        VIR_DEBUG("Define node device '%s' with mdevctl", def->name);
        if (virMdevctlDefine(def, &uuid) < 0)
            return NULL;

        if (uuid && uuid[0]) {
            g_free(def->caps->data.mdev.uuid);
            def->caps->data.mdev.uuid = g_steal_pointer(&uuid);
        }
    }

    mdevGenerateDeviceName(def);
    name = g_strdup(def->name);

    /* Normally we would call nodeDeviceFindNewMediatedDevice() here to wait
     * for the new device to appear. But mdevctl can take a while to query
     * devices, and if nodeDeviceFindNewMediatedDevice() doesn't find the new
     * device immediately it will wait for 5s before checking again. Since we
     * have already received the uuid from virMdevctlDefine(), we can simply
     * add the provisional device to the list and return it immediately and
     * avoid this long delay. */
    if (nodeDeviceUpdateMediatedDevice(g_steal_pointer(&def), true) < 0)
        return NULL;

    return virGetNodeDevice(conn, name);
}


int
nodeDeviceUndefine(virNodeDevice *device,
                   unsigned int flags)
{
    int ret = -1;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;

    virCheckFlags(0, -1);

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;

    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceUndefineEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (!virNodeDeviceObjIsPersistent(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Node device '%1$s' is not defined"),
                       def->name);
        goto cleanup;
    }

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        if (virMdevctlUndefine(def) < 0)
            goto cleanup;

        ret = 0;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeDeviceCreate(virNodeDevice *device,
                 unsigned int flags)
{
    int ret = -1;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def = NULL;

    virCheckFlags(0, -1);

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;

    if (virNodeDeviceObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Device is already active"));
        goto cleanup;
    }
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceCreateEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        if (virMdevctlStart(def) < 0)
            goto cleanup;

        ret = 0;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                      virNodeDevicePtr device,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    int callbackID = -1;

    if (virConnectNodeDeviceEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (virNodeDeviceEventStateRegisterID(conn, driver->nodeDeviceEventState,
                                          device, eventID, callback,
                                          opaque, freecb, &callbackID) < 0)
        callbackID = -1;

    return callbackID;
}


int
nodeConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                        int callbackID)
{
    if (virConnectNodeDeviceEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->nodeDeviceEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}

int
nodedevRegister(void)
{
#ifdef WITH_UDEV
    return udevNodeRegister();
#endif
}


void
nodeDeviceGenerateName(virNodeDeviceDef *def,
                       const char *subsystem,
                       const char *sysname,
                       const char *s)
{
    size_t i;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s_%s",
                      subsystem,
                      sysname);

    if (s != NULL)
        virBufferAsprintf(&buf, "_%s", s);

    g_free(def->name);
    def->name = virBufferContentAndReset(&buf);

    for (i = 0; i < strlen(def->name); i++) {
        if (!(g_ascii_isalnum(*(def->name + i))))
            *(def->name + i) = '_';
    }
}


static int
virMdevctlList(bool defined,
               virNodeDeviceDef ***devs,
               char **errmsg)
{
    int status;
    g_autofree char *output = NULL;
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = nodeDeviceGetMdevctlListCommand(defined, &output, &errbuf);

    if (virCommandRun(cmd, &status) < 0 || status != 0) {
        *errmsg = g_steal_pointer(&errbuf);
        return -1;
    }

    return nodeDeviceParseMdevctlJSON(output, devs, defined);
}


typedef struct _virMdevctlForEachData virMdevctlForEachData;
struct _virMdevctlForEachData {
    int ndefs;
    virNodeDeviceDef **defs;
};


/* This function keeps the list of persistent mediated devices consistent
 * between the nodedev driver and mdevctl.
 * @obj is a device that is currently known by the nodedev driver, and @opaque
 * contains the most recent list of devices defined by mdevctl. If @obj is no
 * longer defined in mdevctl, mark it as undefined and possibly remove it from
 * the driver as well. Returning 'true' from this function indicates that the
 * device should be removed from the nodedev driver list. */
static bool
removeMissingPersistentMdev(virNodeDeviceObj *obj,
                            const void *opaque)
{
    bool remove = false;
    const virMdevctlForEachData *data = opaque;
    size_t i;
    virNodeDeviceDef *def = virNodeDeviceObjGetDef(obj);
    virObjectEvent *event;

    if (def->caps->data.type != VIR_NODE_DEV_CAP_MDEV)
        return false;

    /* transient mdevs are populated via udev, so don't remove them from the
     * nodedev driver just because they are not reported by by mdevctl */
    if (!virNodeDeviceObjIsPersistent(obj))
        return false;

    for (i = 0; i < data->ndefs; i++) {
        /* OK, this mdev is still defined by mdevctl
         * AND the parent object has not changed. */
        if (STREQ(data->defs[i]->name, def->name) &&
            STREQ(data->defs[i]->parent, def->parent))
            return false;
    }

    event = virNodeDeviceEventLifecycleNew(def->name,
                                           VIR_NODE_DEVICE_EVENT_UNDEFINED,
                                           0);

    /* The device is active, but no longer defined by mdevctl. Keep the device
     * in the list, but mark it as non-persistent */
    if (virNodeDeviceObjIsActive(obj)) {
        virNodeDeviceObjSetAutostart(obj, false);
        virNodeDeviceObjSetPersistent(obj, false);
    } else {
        remove = true;
    }

    virObjectEventStateQueue(driver->nodeDeviceEventState, event);

    return remove;
}


int
nodeDeviceUpdateMediatedDevices(void)
{
    g_autofree virNodeDeviceDef **defs = NULL;
    g_autofree virNodeDeviceDef **act_defs = NULL;
    int act_ndefs = 0;
    g_autofree char *errmsg = NULL;
    g_autofree char *mdevctl = NULL;
    virMdevctlForEachData data = { 0, };
    size_t i;

    if (!(mdevctl = virFindFileInPath(MDEVCTL))) {
        VIR_DEBUG(MDEVCTL " not found. Skipping update of mediated devices.");
        return 0;
    }

    if ((data.ndefs = virMdevctlList(true, &defs, &errmsg)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to query mdevs from mdevctl: %1$s"), errmsg);
        return -1;
    }

    /* Any mdevs that were previously defined but were not returned in the
     * latest mdevctl query should be removed from the device list */
    data.defs = defs;
    virNodeDeviceObjListForEachRemove(driver->devs,
                                      removeMissingPersistentMdev, &data);

    for (i = 0; i < data.ndefs; i++)
        if (nodeDeviceUpdateMediatedDevice(defs[i], true) < 0)
            return -1;

    /* Update active/transient mdev devices */
    if ((act_ndefs = virMdevctlList(false, &act_defs, &errmsg)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to query mdevs from mdevctl: %1$s"), errmsg);
        return -1;
    }

    for (i = 0; i < act_ndefs; i++)
        if (nodeDeviceUpdateMediatedDevice(act_defs[i], false) < 0)
            return -1;

    return 0;
}


/* returns true if any attributes were copied, else returns false */
static bool
virMediatedDeviceAttrsCopy(virMediatedDeviceConfig *dst_config,
                           virMediatedDeviceConfig *src_config)
{
    bool ret = false;
    size_t i;

    if (src_config->nattributes != dst_config->nattributes) {
        ret = true;
        for (i = 0; i < dst_config->nattributes; i++)
            virMediatedDeviceAttrFree(dst_config->attributes[i]);
        g_free(dst_config->attributes);

        dst_config->nattributes = src_config->nattributes;
        dst_config->attributes = g_new0(virMediatedDeviceAttr*,
                                 src_config->nattributes);
        for (i = 0; i < dst_config->nattributes; i++)
            dst_config->attributes[i] = virMediatedDeviceAttrNew();
    }

    for (i = 0; i < src_config->nattributes; i++) {
        if (STRNEQ_NULLABLE(src_config->attributes[i]->name,
                            dst_config->attributes[i]->name)) {
            ret = true;
            g_free(dst_config->attributes[i]->name);
            dst_config->attributes[i]->name =
                g_strdup(src_config->attributes[i]->name);
        }
        if (STRNEQ_NULLABLE(src_config->attributes[i]->value,
                            dst_config->attributes[i]->value)) {
            ret = true;
            g_free(dst_config->attributes[i]->value);
            dst_config->attributes[i]->value =
                g_strdup(src_config->attributes[i]->value);
        }
    }

    return ret;
}


/* A mediated device definitions from mdevctl contains additional info that is
 * not available from udev. Transfer this data to the new definition.
 * Returns true if anything was copied, else returns false */
bool
nodeDeviceDefCopyFromMdevctl(virNodeDeviceDef *dst,
                             virNodeDeviceDef *src,
                             bool defined)
{
    bool ret = false;
    virNodeDevCapMdev *srcmdev = &src->caps->data.mdev;
    virNodeDevCapMdev *dstmdev = &dst->caps->data.mdev;
    virMediatedDeviceConfig *srcmdevconfig = &src->caps->data.mdev.active_config;
    virMediatedDeviceConfig *dstmdevconfig = &dst->caps->data.mdev.active_config;

    if (defined) {
        srcmdevconfig = &src->caps->data.mdev.defined_config;
        dstmdevconfig = &dst->caps->data.mdev.defined_config;
    }

    if (STRNEQ_NULLABLE(dstmdevconfig->type, srcmdevconfig->type)) {
        ret = true;
        g_free(dstmdevconfig->type);
        dstmdevconfig->type = g_strdup(srcmdevconfig->type);
    }

    if (STRNEQ_NULLABLE(dstmdev->uuid, srcmdev->uuid)) {
        ret = true;
        g_free(dstmdev->uuid);
        dstmdev->uuid = g_strdup(srcmdev->uuid);
    }

    if (virMediatedDeviceAttrsCopy(dstmdevconfig, srcmdevconfig))
        ret = true;

    if (dstmdev->autostart != srcmdev->autostart) {
        ret = true;
        dstmdev->autostart = srcmdev->autostart;
    }

    return ret;
}


int
nodeDeviceSetAutostart(virNodeDevice *device,
                       int autostart)
{
    int ret = -1;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def = NULL;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceSetAutostartEnsureACL(device->conn, def) < 0)
        goto cleanup;

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV)) {
        if (!virNodeDeviceObjIsPersistent(obj)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cannot set autostart for transient device"));
            goto cleanup;
        }

        if (autostart != virNodeDeviceObjIsAutostart(obj)) {
            g_autofree char *errmsg = NULL;

            if (virMdevctlSetAutostart(def, autostart, &errmsg) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to set autostart on '%1$s': %2$s"),
                               def->name,
                               errmsg && errmsg[0] != '\0' ? errmsg : _("Unknown Error"));
                goto cleanup;
            }
            /* Due to mdevctl performance issues, it may take several seconds
             * to re-query mdevctl for the defined devices. Because the mdevctl
             * command returned without an error status, assume it was
             * successful and set the object status directly here rather than
             * waiting for the next query */
            virNodeDeviceObjSetAutostart(obj, autostart);
        }
        ret = 0;
    } else {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
    }

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeDeviceGetAutostart(virNodeDevice *device,
                       int *autostart)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def = NULL;
    int ret = -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceGetAutostartEnsureACL(device->conn, def) < 0)
        goto cleanup;

    *autostart = virNodeDeviceObjIsAutostart(obj);
    ret = 0;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int nodeDeviceDefPostParse(virNodeDeviceDef *def,
                           G_GNUC_UNUSED void *opaque)
{
    virNodeDevCapsDef *caps = NULL;
    for (caps = def->caps; caps != NULL; caps = caps->next) {
        if (caps->data.type == VIR_NODE_DEV_CAP_MDEV) {
            virNodeDeviceObj *obj = NULL;

            if (def->parent)
                obj = virNodeDeviceObjListFindByName(driver->devs, def->parent);

            if (obj) {
                caps->data.mdev.parent_addr = nodeDeviceObjFormatAddress(obj);
                virNodeDeviceObjEndAPI(&obj);
            }
        }
    }
    return 0;
}


/* validate that parent exists */
static int nodeDeviceDefValidateMdev(virNodeDeviceDef *def,
                                     virNodeDevCapMdev *mdev,
                                     G_GNUC_UNUSED void *opaque)
{
    virNodeDeviceObj *obj = NULL;
    if (!def->parent) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing parent device"));
        return -1;
    }
    obj = virNodeDeviceObjListFindByName(driver->devs, def->parent);
    if (!obj) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid parent device '%1$s'"),
                       def->parent);
        return -1;
    }
    virNodeDeviceObjEndAPI(&obj);

    /* the post-parse callback should have found the address of the parent
     * device and stored it in the mdev caps */
    if (!mdev->parent_addr) {
        virReportError(VIR_ERR_PARSE_FAILED,
                       _("Unable to find address for parent device '%1$s'"),
                       def->parent);
        return -1;
    }

    return 0;
}

int nodeDeviceDefValidate(virNodeDeviceDef *def,
                          G_GNUC_UNUSED void *opaque)
{
    virNodeDevCapsDef *caps = NULL;
    for (caps = def->caps; caps != NULL; caps = caps->next) {
        switch (caps->data.type) {
            case VIR_NODE_DEV_CAP_MDEV:
                if (nodeDeviceDefValidateMdev(def, &caps->data.mdev, opaque) < 0)
                    return -1;
                break;

            case VIR_NODE_DEV_CAP_SYSTEM:
            case VIR_NODE_DEV_CAP_PCI_DEV:
            case VIR_NODE_DEV_CAP_USB_DEV:
            case VIR_NODE_DEV_CAP_USB_INTERFACE:
            case VIR_NODE_DEV_CAP_NET:
            case VIR_NODE_DEV_CAP_SCSI_HOST:
            case VIR_NODE_DEV_CAP_SCSI_TARGET:
            case VIR_NODE_DEV_CAP_SCSI:
            case VIR_NODE_DEV_CAP_STORAGE:
            case VIR_NODE_DEV_CAP_FC_HOST:
            case VIR_NODE_DEV_CAP_VPORTS:
            case VIR_NODE_DEV_CAP_SCSI_GENERIC:
            case VIR_NODE_DEV_CAP_DRM:
            case VIR_NODE_DEV_CAP_MDEV_TYPES:
            case VIR_NODE_DEV_CAP_CCW_DEV:
            case VIR_NODE_DEV_CAP_CSS_DEV:
            case VIR_NODE_DEV_CAP_VDPA:
            case VIR_NODE_DEV_CAP_AP_CARD:
            case VIR_NODE_DEV_CAP_AP_QUEUE:
            case VIR_NODE_DEV_CAP_AP_MATRIX:
            case VIR_NODE_DEV_CAP_VPD:
            case VIR_NODE_DEV_CAP_LAST:
                break;
        }
    }
    return 0;
}


int
nodeDeviceIsPersistent(virNodeDevice *device)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def = NULL;
    int ret = -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceIsPersistentEnsureACL(device->conn, def) < 0)
        goto cleanup;

    ret = virNodeDeviceObjIsPersistent(obj);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


int
nodeDeviceIsActive(virNodeDevice *device)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def = NULL;
    int ret = -1;

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    if (virNodeDeviceIsActiveEnsureACL(device->conn, def) < 0)
        goto cleanup;

    ret = virNodeDeviceObjIsActive(obj);

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}


static int
nodeDeviceDefValidateUpdate(virNodeDeviceDef *def,
                            virNodeDeviceDef *new_def,
                            bool live)
{
    virNodeDevCapsDef *caps = NULL;
    virNodeDevCapMdev *cap_mdev = NULL;
    virNodeDevCapMdev *cap_new_mdev = NULL;

    for (caps = def->caps; caps != NULL; caps = caps->next) {
        if (caps->data.type == VIR_NODE_DEV_CAP_MDEV) {
            cap_mdev = &caps->data.mdev;
        }
    }
    if (!cap_mdev)
        return -1;

    for (caps = new_def->caps; caps != NULL; caps = caps->next) {
        if (caps->data.type == VIR_NODE_DEV_CAP_MDEV) {
            cap_new_mdev = &caps->data.mdev;
        }
    }
    if (!cap_new_mdev)
        return -1;

    if (STRNEQ_NULLABLE(cap_mdev->uuid, cap_new_mdev->uuid)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot update device '%1$s, uuid mismatch (current uuid '%2$s')"),
                       def->name,
                       cap_mdev->uuid);
        return -1;
    }

    /* A live update cannot change the mdev type. Since the new config is
     * stored in defined_config, compare that to the mdev type of the current
     * live config to make sure they match */
    if (live &&
        STRNEQ_NULLABLE(cap_mdev->active_config.type, cap_new_mdev->defined_config.type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot update device '%1$s', type mismatch (current type '%2$s')"),
                       def->name,
                       cap_mdev->active_config.type);
        return -1;
    }
    if (STRNEQ_NULLABLE(cap_mdev->parent_addr, cap_new_mdev->parent_addr)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot update device '%1$s', parent address mismatch (current parent address '%2$s')"),
                       def->name,
                       cap_mdev->parent_addr);
        return -1;
    }

    return 0;
}


int
nodeDeviceUpdate(virNodeDevice *device,
                 const char *xmlDesc,
                 unsigned int flags)
{
    int ret = -1;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;
    g_autoptr(virNodeDeviceDef) new_def = NULL;
    const char *virt_type = NULL;
    bool updated = false;

    virCheckFlags(VIR_NODE_DEVICE_UPDATE_AFFECT_LIVE |
                  VIR_NODE_DEVICE_UPDATE_AFFECT_CONFIG, -1);

    if (nodeDeviceInitWait() < 0)
        return -1;

    if (!(obj = nodeDeviceObjFindByName(device->name)))
        return -1;
    def = virNodeDeviceObjGetDef(obj);

    virt_type = virConnectGetType(device->conn);

    if (virNodeDeviceUpdateEnsureACL(device->conn, def, flags) < 0)
        goto cleanup;

    if (!(new_def = virNodeDeviceDefParse(xmlDesc, NULL, EXISTING_DEVICE, virt_type,
                                          &driver->parserCallbacks, NULL, true)))
        goto cleanup;

    if (nodeDeviceHasCapability(def, VIR_NODE_DEV_CAP_MDEV) &&
        nodeDeviceHasCapability(new_def, VIR_NODE_DEV_CAP_MDEV)) {
        /* Checks flags are valid for the state and sets flags for
         * current if flags not set. */
        if (virNodeDeviceObjUpdateModificationImpact(obj, &flags) < 0)
            goto cleanup;

        /* Compare def and new_def for compatibility e.g. parent, type
         * and uuid. */
        if (nodeDeviceDefValidateUpdate(def, new_def,
                                        (flags & VIR_NODE_DEVICE_UPDATE_AFFECT_LIVE)) < 0)
            goto cleanup;

        /* Update now. */
        VIR_DEBUG("Update node device '%s' with mdevctl", def->name);
        if (virMdevctlModify(new_def,
                             (flags & VIR_NODE_DEVICE_UPDATE_AFFECT_CONFIG),
                             (flags & VIR_NODE_DEVICE_UPDATE_AFFECT_LIVE)) < 0) {
            goto cleanup;
        };
        /* Detect updates and also trigger events. */
        updated = true;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported device type"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    if (updated)
        nodeDeviceUpdateMediatedDevices();

    return ret;
}
