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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
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

    if (!vshConnectionUsability(ctl, ctl->conn)) {
        return false;
    }

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
    {"cap", VSH_OT_STRING, VSH_OFLAG_NONE, N_("capability name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeListDevices(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *cap = NULL;
    char **devices;
    int num_devices, i;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "cap", &cap) <= 0)
        cap = NULL;

    num_devices = virNodeNumOfDevices(ctl->conn, cap, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to count node devices"));
        return false;
    } else if (num_devices == 0) {
        return true;
    }

    devices = vshMalloc(ctl, sizeof(char *) * num_devices);
    num_devices =
        virNodeListDevices(ctl->conn, cap, devices, num_devices, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to list node devices"));
        VIR_FREE(devices);
        return false;
    }
    qsort(&devices[0], num_devices, sizeof(char*), vshNameSorter);
    if (tree) {
        char **parents = vshMalloc(ctl, sizeof(char *) * num_devices);
        struct vshNodeList arrays = { devices, parents };

        for (i = 0; i < num_devices; i++) {
            virNodeDevicePtr dev = virNodeDeviceLookupByName(ctl->conn, devices[i]);
            if (dev && STRNEQ(devices[i], "computer")) {
                const char *parent = virNodeDeviceGetParent(dev);
                parents[i] = parent ? vshStrdup(ctl, parent) : NULL;
            } else {
                parents[i] = NULL;
            }
            virNodeDeviceFree(dev);
        }
        for (i = 0 ; i < num_devices ; i++) {
            if (parents[i] == NULL &&
                vshTreePrint(ctl, vshNodeListLookup, &arrays, num_devices,
                             i) < 0)
                ret = false;
        }
        for (i = 0 ; i < num_devices ; i++) {
            VIR_FREE(devices[i]);
            VIR_FREE(parents[i]);
        }
        VIR_FREE(parents);
    } else {
        for (i = 0; i < num_devices; i++) {
            vshPrint(ctl, "%s\n", devices[i]);
            VIR_FREE(devices[i]);
        }
    }
    VIR_FREE(devices);
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
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

static const vshCmdDef nodedevCmds[] = {
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
