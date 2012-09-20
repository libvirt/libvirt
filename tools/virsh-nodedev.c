/*
 * virsh-nodedev.c: Commands in node device group
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>
#include "virsh-nodedev.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "buf.h"
#include "memory.h"
#include "util.h"
#include "xml.h"
#include "conf/node_device_conf.h"

/*
 * "nodedev-create" command
 */
static const vshCmdInfo info_node_device_create[] = {
    {"help", N_("create a device defined "
                          "by an XML file on the node")},
    {"desc", N_("Create a device on the node.  Note that this "
                          "command creates devices on the physical host "
                          "that can then be assigned to a virtual machine.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("file containing an XML description of the device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    dev = virNodeDeviceCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (dev != NULL) {
        vshPrint(ctl, _("Node device %s created from %s\n"),
                 virNodeDeviceGetName(dev), from);
        virNodeDeviceFree(dev);
    } else {
        vshError(ctl, _("Failed to create node device from %s"), from);
        ret = false;
    }

    return ret;
}


/*
 * "nodedev-destroy" command
 */
static const vshCmdInfo info_node_device_destroy[] = {
    {"help", N_("destroy (stop) a device on the node")},
    {"desc", N_("Destroy a device on the node.  Note that this "
                "command destroys devices on the physical host")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_destroy[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("name of the device to be destroyed")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    bool ret = true;
    const char *name = NULL;

    if (vshCommandOptString(cmd, "name", &name) <= 0)
        return false;

    dev = virNodeDeviceLookupByName(ctl->conn, name);

    if (virNodeDeviceDestroy(dev) == 0) {
        vshPrint(ctl, _("Destroyed node device '%s'\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy node device '%s'"), name);
        ret = false;
    }

    virNodeDeviceFree(dev);
    return ret;
}

struct vshNodeList {
    char **names;
    char **parents;
};

static const char *
vshNodeListLookup(int devid, bool parent, void *opaque)
{
    struct vshNodeList *arrays = opaque;
    if (parent)
        return arrays->parents[devid];
    return arrays->names[devid];
}

static int
vshNodeDeviceSorter(const void *a, const void *b)
{
    virNodeDevicePtr *na = (virNodeDevicePtr *) a;
    virNodeDevicePtr *nb = (virNodeDevicePtr *) b;

    if (*na && !*nb)
        return -1;

    if (!*na)
        return *nb != NULL;

    return vshStrcasecmp(virNodeDeviceGetName(*na),
                         virNodeDeviceGetName(*nb));
}

struct vshNodeDeviceList {
    virNodeDevicePtr *devices;
    size_t ndevices;
};
typedef struct vshNodeDeviceList *vshNodeDeviceListPtr;

static void
vshNodeDeviceListFree(vshNodeDeviceListPtr list)
{
    int i;

    if (list && list->ndevices) {
        for (i = 0; i < list->ndevices; i++) {
            if (list->devices[i])
                virNodeDeviceFree(list->devices[i]);
        }
        VIR_FREE(list->devices);
    }
    VIR_FREE(list);
}

static vshNodeDeviceListPtr
vshNodeDeviceListCollect(vshControl *ctl,
                         char **capnames,
                         int ncapnames,
                         unsigned int flags)
{
    vshNodeDeviceListPtr list = vshMalloc(ctl, sizeof(*list));
    int i;
    int ret;
    virNodeDevicePtr device;
    bool success = false;
    size_t deleted = 0;
    int ndevices = 0;
    char **names = NULL;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllNodeDevices(ctl->conn,
                                            &list->devices,
                                            flags)) >= 0) {
        list->ndevices = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    /* there was an error during the call */
    vshError(ctl, "%s", _("Failed to list node devices"));
    goto cleanup;


fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    ndevices = virNodeNumOfDevices(ctl->conn, NULL, 0);
    if (ndevices < 0) {
        vshError(ctl, "%s", _("Failed to count node devices"));
        goto cleanup;
    }

    if (ndevices == 0)
        return list;

    names = vshMalloc(ctl, sizeof(char *) * ndevices);

    ndevices = virNodeListDevices(ctl->conn, NULL, names, ndevices, 0);
    if (ndevices < 0) {
        vshError(ctl, "%s", _("Failed to list node devices"));
        goto cleanup;
    }

    list->devices = vshMalloc(ctl, sizeof(virNodeDevicePtr) * (ndevices));
    list->ndevices = 0;

    /* get the node devices */
    for (i = 0; i < ndevices ; i++) {
        if (!(device = virNodeDeviceLookupByName(ctl->conn, names[i])))
            continue;
        list->devices[list->ndevices++] = device;
    }

    /* truncate domains that weren't found */
    deleted = ndevices - list->ndevices;

    if (!capnames)
        goto finished;

    /* filter the list if the list was acquired by fallback means */
    for (i = 0; i < list->ndevices; i++) {
        char **caps = NULL;
        int ncaps = 0;
        bool match = false;

        device = list->devices[i];

        if ((ncaps = virNodeDeviceNumOfCaps(device)) < 0) {
            vshError(ctl, "%s", _("Failed to get capability numbers "
                                  "of the device"));
            goto cleanup;
        }

        caps = vshMalloc(ctl, sizeof(char *) * ncaps);

        if ((ncaps = virNodeDeviceListCaps(device, caps, ncaps)) < 0) {
            vshError(ctl, "%s", _("Failed to get capability names of the device"));
            VIR_FREE(caps);
            goto cleanup;
        }

        /* Check if the device's capability matches with provied
         * capabilities.
         */
        int j, k;
        for (j = 0; j < ncaps; j++) {
            for (k = 0; k < ncapnames; k++) {
                if (STREQ(caps[j], capnames[k])) {
                    match = true;
                    break;
                }
            }
        }

        VIR_FREE(caps);

        if (!match)
            goto remove_entry;

        /* the device matched all filters, it may stay */
        continue;

remove_entry:
        /* the device has to be removed as it failed one of the filters */
        virNodeDeviceFree(list->devices[i]);
        list->devices[i] = NULL;
        deleted++;
    }

finished:
    /* sort the list */
    if (list->devices && list->ndevices)
        qsort(list->devices, list->ndevices,
              sizeof(*list->devices), vshNodeDeviceSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->devices, list->ndevices, deleted);

    success = true;

cleanup:
    for (i = 0; i < ndevices; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        vshNodeDeviceListFree(list);
        list = NULL;
    }

    return list;
}

/*
 * "nodedev-list" command
 */
static const vshCmdInfo info_node_list_devices[] = {
    {"help", N_("enumerate devices on this host")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_list_devices[] = {
    {"tree", VSH_OT_BOOL, 0, N_("list devices in a tree")},
    {"cap", VSH_OT_STRING, VSH_OFLAG_NONE, N_("capability names, separated by comma")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeListDevices(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *cap_str = NULL;
    int i;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool ret = true;
    unsigned int flags = 0;
    char **caps = NULL;
    int ncaps = 0;
    vshNodeDeviceListPtr list = NULL;
    int cap_type = -1;

    ignore_value(vshCommandOptString(cmd, "cap", &cap_str));

    if (cap_str) {
        if (tree) {
            vshError(ctl, "%s", _("Options --tree and --cap are incompatible"));
            return false;
        }
        ncaps = vshStringToArray(cap_str, &caps);
    }

    for (i = 0; i < ncaps; i++) {
        if ((cap_type = virNodeDevCapTypeFromString(caps[i])) < 0) {
            vshError(ctl, "%s", _("Invalid capability type"));
            VIR_FREE(caps);
            return false;
        }

        switch(cap_type) {
        case VIR_NODE_DEV_CAP_SYSTEM:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM;
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV;
            break;
        case VIR_NODE_DEV_CAP_USB_DEV:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV;
            break;
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE;
            break;
        case VIR_NODE_DEV_CAP_NET:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET;
            break;
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST;
            break;
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET;
            break;
        case VIR_NODE_DEV_CAP_SCSI:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI;
            break;
        case VIR_NODE_DEV_CAP_STORAGE:
            flags |= VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE;
            break;
        default:
            break;
        }
    }

    if (!(list = vshNodeDeviceListCollect(ctl, caps, ncaps, flags))) {
        ret = false;
        goto cleanup;
    }

    if (tree) {
        char **parents = vshMalloc(ctl, sizeof(char *) * list->ndevices);
        char **names = vshMalloc(ctl, sizeof(char *) * list->ndevices);
        struct vshNodeList arrays = { names, parents };

        for (i = 0; i < list->ndevices; i++)
            names[i] = vshStrdup(ctl, virNodeDeviceGetName(list->devices[i]));

        for (i = 0; i < list->ndevices; i++) {
            virNodeDevicePtr dev = list->devices[i];
            if (STRNEQ(names[i], "computer")) {
                const char *parent = virNodeDeviceGetParent(dev);
                parents[i] = parent ? vshStrdup(ctl, parent) : NULL;
            } else {
                parents[i] = NULL;
            }
        }

        for (i = 0 ; i < list->ndevices; i++) {
            if (parents[i] == NULL &&
                vshTreePrint(ctl, vshNodeListLookup, &arrays,
                             list->ndevices, i) < 0)
                ret = false;
        }

        for (i = 0 ; i < list->ndevices; i++)
            VIR_FREE(parents[i]);
        VIR_FREE(parents);
        for (i = 0; i < list->ndevices; i++)
            VIR_FREE(names[i]);
        VIR_FREE(names);
    } else {
        for (i = 0; i < list->ndevices; i++)
            vshPrint(ctl, "%s\n", virNodeDeviceGetName(list->devices[i]));
    }

cleanup:
    if (caps) {
        VIR_FREE(*caps);
        VIR_FREE(caps);
    }
    vshNodeDeviceListFree(list);
    return ret;
}

/*
 * "nodedev-dumpxml" command
 */
static const vshCmdInfo info_node_device_dumpxml[] = {
    {"help", N_("node device details in XML")},
    {"desc", N_("Output the node device details as an XML dump to stdout.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_dumpxml[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    char *xml;

    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    xml = virNodeDeviceGetXMLDesc(device, 0);
    if (!xml) {
        virNodeDeviceFree(device);
        return false;
    }

    vshPrint(ctl, "%s\n", xml);
    VIR_FREE(xml);
    virNodeDeviceFree(device);
    return true;
}

/*
 * "nodedev-detach" command
 */
static const vshCmdInfo info_node_device_detach[] = {
    {"help", N_("detach node device from its device driver")},
    {"desc", N_("Detach node device from its device driver before assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_detach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDetach(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    /* Yes, our public API is misspelled.  At least virsh can accept
     * either spelling.  */
    if (virNodeDeviceDettach(device) == 0) {
        vshPrint(ctl, _("Device %s detached\n"), name);
    } else {
        vshError(ctl, _("Failed to detach device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "nodedev-reattach" command
 */
static const vshCmdInfo info_node_device_reattach[] = {
    {"help", N_("reattach node device to its device driver")},
    {"desc", N_("Reattach node device to its device driver once released by the domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reattach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceReAttach(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    if (virNodeDeviceReAttach(device) == 0) {
        vshPrint(ctl, _("Device %s re-attached\n"), name);
    } else {
        vshError(ctl, _("Failed to re-attach device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "nodedev-reset" command
 */
static const vshCmdInfo info_node_device_reset[] = {
    {"help", N_("reset node device")},
    {"desc", N_("Reset node device before or after assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reset[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceReset(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    if (virNodeDeviceReset(device) == 0) {
        vshPrint(ctl, _("Device %s reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

const vshCmdDef nodedevCmds[] = {
    {"nodedev-create", cmdNodeDeviceCreate, opts_node_device_create,
     info_node_device_create, 0},
    {"nodedev-destroy", cmdNodeDeviceDestroy, opts_node_device_destroy,
     info_node_device_destroy, 0},
    {"nodedev-detach", cmdNodeDeviceDetach, opts_node_device_detach,
     info_node_device_detach, 0},
    {"nodedev-dettach", cmdNodeDeviceDetach, opts_node_device_detach,
     info_node_device_detach, VSH_CMD_FLAG_ALIAS},
    {"nodedev-dumpxml", cmdNodeDeviceDumpXML, opts_node_device_dumpxml,
     info_node_device_dumpxml, 0},
    {"nodedev-list", cmdNodeListDevices, opts_node_list_devices,
     info_node_list_devices, 0},
    {"nodedev-reattach", cmdNodeDeviceReAttach, opts_node_device_reattach,
     info_node_device_reattach, 0},
    {"nodedev-reset", cmdNodeDeviceReset, opts_node_device_reset,
     info_node_device_reset, 0},
    {NULL, NULL, NULL, NULL, 0}
};
