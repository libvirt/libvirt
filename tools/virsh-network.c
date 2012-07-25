/*
 * virsh-network.c: Commands to manage network
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

/* default is lookup by Name and UUID */
#define vshCommandOptNetwork(_ctl, _cmd, _name)                    \
    vshCommandOptNetworkBy(_ctl, _cmd, _name,                      \
                           VSH_BYUUID|VSH_BYNAME)

static virNetworkPtr
vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                       const char **name, int flag)
{
    virNetworkPtr network = NULL;
    const char *n = NULL;
    const char *optname = "network";
    if (!cmd_has_option(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && strlen(n) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network UUID\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (network==NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network NAME\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByName(ctl->conn, n);
    }

    if (!network)
        vshError(ctl, _("failed to get network '%s'"), n);

    return network;
}

/*
 * "net-autostart" command
 */
static const vshCmdInfo info_network_autostart[] = {
    {"help", N_("autostart a network")},
    {"desc",
     N_("Configure a network to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_autostart[] = {
    {"network",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {"disable", VSH_OT_BOOL, 0, N_("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virNetworkSetAutostart(network, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark network %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark network %s as autostarted"), name);
        virNetworkFree(network);
        return false;
    }

    if (autostart)
        vshPrint(ctl, _("Network %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Network %s unmarked as autostarted\n"), name);

    virNetworkFree(network);
    return true;
}

/*
 * "net-create" command
 */
static const vshCmdInfo info_network_create[] = {
    {"help", N_("create a network from an XML file")},
    {"desc", N_("Create a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    network = virNetworkCreateXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s created from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to create network from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "net-define" command
 */
static const vshCmdInfo info_network_define[] = {
    {"help", N_("define (but don't start) a network from an XML file")},
    {"desc", N_("Define a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    network = virNetworkDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s defined from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to define network from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "net-destroy" command
 */
static const vshCmdInfo info_network_destroy[] = {
    {"help", N_("destroy (stop) a network")},
    {"desc", N_("Forcefully stop a given network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_destroy[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkDestroy(network) == 0) {
        vshPrint(ctl, _("Network %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy network %s"), name);
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}

/*
 * "net-dumpxml" command
 */
static const vshCmdInfo info_network_dumpxml[] = {
    {"help", N_("network information in XML")},
    {"desc", N_("Output the network information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_dumpxml[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {"inactive", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("network information of an inactive domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    int inactive;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    inactive = vshCommandOptBool(cmd, "inactive");
    if (inactive)
        flags |= VIR_NETWORK_XML_INACTIVE;

    dump = virNetworkGetXMLDesc(network, flags);

    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}

/*
 * "net-info" command
 */
static const vshCmdInfo info_network_info[] = {
    {"help", N_("network information")},
    {"desc", N_("Returns basic information about the network")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_info[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkInfo(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int autostart;
    int persistent = -1;
    int active = -1;
    char *bridge = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name"), virNetworkGetName(network));

    if (virNetworkGetUUIDString(network, uuid) == 0)
        vshPrint(ctl, "%-15s %s\n", _("UUID"), uuid);

    active = virNetworkIsActive(network);
    if (active >= 0)
        vshPrint(ctl, "%-15s %s\n", _("Active:"), active? _("yes") : _("no"));

    persistent = virNetworkIsPersistent(network);
    if (persistent < 0)
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

    if (virNetworkGetAutostart(network, &autostart) < 0)
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"), _("no autostart"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"), autostart ? _("yes") : _("no"));

    bridge = virNetworkGetBridgeName(network);
    if (bridge)
        vshPrint(ctl, "%-15s %s\n", _("Bridge:"), bridge);

    VIR_FREE(bridge);
    virNetworkFree(network);
    return true;
}

/*
 * "net-list" command
 */
static const vshCmdInfo info_network_list[] = {
    {"help", N_("list networks")},
    {"desc", N_("Returns list of networks.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive networks")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active networks")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool all = vshCommandOptBool(cmd, "all");
    bool active = !inactive || all;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (active) {
        maxactive = virConnectNumOfNetworks(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active networks"));
            return false;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListNetworks(ctl->conn, activeNames,
                                                    maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active networks"));
                VIR_FREE(activeNames);
                return false;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), vshNameSorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedNetworks(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive networks"));
            VIR_FREE(activeNames);
            return false;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive =
                     virConnectListDefinedNetworks(ctl->conn, inactiveNames,
                                                   maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive networks"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return false;
            }

            qsort(&inactiveNames[0], maxinactive, sizeof(char*), vshNameSorter);
        }
    }
    vshPrintExtra(ctl, "%-20s %-10s %s\n", _("Name"), _("State"),
                  _("Autostart"));
    vshPrintExtra(ctl, "-----------------------------------------\n");

    for (i = 0; i < maxactive; i++) {
        virNetworkPtr network =
            virNetworkLookupByName(ctl->conn, activeNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with networks is not atomic operation */
        if (!network) {
            VIR_FREE(activeNames[i]);
            continue;
        }

        if (virNetworkGetAutostart(network, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? _("yes") : _("no");

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 virNetworkGetName(network),
                 _("active"),
                 autostartStr);
        virNetworkFree(network);
        VIR_FREE(activeNames[i]);
    }
    for (i = 0; i < maxinactive; i++) {
        virNetworkPtr network = virNetworkLookupByName(ctl->conn, inactiveNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with networks is not atomic operation */
        if (!network) {
            VIR_FREE(inactiveNames[i]);
            continue;
        }

        if (virNetworkGetAutostart(network, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? _("yes") : _("no");

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 inactiveNames[i],
                 _("inactive"),
                 autostartStr);

        virNetworkFree(network);
        VIR_FREE(inactiveNames[i]);
    }
    VIR_FREE(activeNames);
    VIR_FREE(inactiveNames);
    return true;
}

/*
 * "net-name" command
 */
static const vshCmdInfo info_network_name[] = {
    {"help", N_("convert a network UUID to network name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_name[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virNetworkGetName(network));
    virNetworkFree(network);
    return true;
}

/*
 * "net-start" command
 */
static const vshCmdInfo info_network_start[] = {
    {"help", N_("start a (previously defined) inactive network")},
    {"desc", N_("Start a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_start[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
         return false;

    if (virNetworkCreate(network) == 0) {
        vshPrint(ctl, _("Network %s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start network %s"), name);
        ret = false;
    }
    virNetworkFree(network);
    return ret;
}

/*
 * "net-undefine" command
 */
static const vshCmdInfo info_network_undefine[] = {
    {"help", N_("undefine an inactive network")},
    {"desc", N_("Undefine the configuration for an inactive network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_undefine[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkUndefine(network) == 0) {
        vshPrint(ctl, _("Network %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network %s"), name);
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}

/*
 * "net-uuid" command
 */
static const vshCmdInfo info_network_uuid[] = {
    {"help", N_("convert a network name to network UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_uuid[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return false;

    if (virNetworkGetUUIDString(network, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get network UUID"));

    virNetworkFree(network);
    return true;
}

/*
 * "net-edit" command
 */
static const vshCmdInfo info_network_edit[] = {
    {"help", N_("edit XML configuration for a network")},
    {"desc", N_("Edit the XML configuration for a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_edit[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static char *vshNetworkGetXMLDesc(virNetworkPtr network)
{
    unsigned int flags = VIR_NETWORK_XML_INACTIVE;
    char *doc = virNetworkGetXMLDesc(network, flags);

    if (!doc && last_error->code == VIR_ERR_INVALID_ARG) {
        /* The server side libvirt doesn't support
         * VIR_NETWORK_XML_INACTIVE, so retry without it.
         */
        vshResetLibvirtError();
        flags &= ~VIR_NETWORK_XML_INACTIVE;
        doc = virNetworkGetXMLDesc(network, flags);
    }
    return doc;
}

static bool
cmdNetworkEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNetworkPtr network = NULL;
    virNetworkPtr network_edited = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    network = vshCommandOptNetwork(ctl, cmd, NULL);
    if (network == NULL)
        goto cleanup;

#define EDIT_GET_XML vshNetworkGetXMLDesc(network)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Network %s XML configuration not changed.\n"), \
             virNetworkGetName(network));                           \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (network_edited = virNetworkDefineXML(ctl->conn, doc_edited))
#define EDIT_FREE \
    if (network_edited) \
        virNetworkFree(network_edited);
#include "virsh-edit.c"

    vshPrint(ctl, _("Network %s XML configuration edited.\n"),
             virNetworkGetName(network_edited));

    ret = true;

 cleanup:
    if (network)
        virNetworkFree(network);
    if (network_edited)
        virNetworkFree(network_edited);

    return ret;
}

static const vshCmdDef networkCmds[] = {
    {"net-autostart", cmdNetworkAutostart, opts_network_autostart,
     info_network_autostart, 0},
    {"net-create", cmdNetworkCreate, opts_network_create,
     info_network_create, 0},
    {"net-define", cmdNetworkDefine, opts_network_define,
     info_network_define, 0},
    {"net-destroy", cmdNetworkDestroy, opts_network_destroy,
     info_network_destroy, 0},
    {"net-dumpxml", cmdNetworkDumpXML, opts_network_dumpxml,
     info_network_dumpxml, 0},
    {"net-edit", cmdNetworkEdit, opts_network_edit, info_network_edit, 0},
    {"net-info", cmdNetworkInfo, opts_network_info, info_network_info, 0},
    {"net-list", cmdNetworkList, opts_network_list, info_network_list, 0},
    {"net-name", cmdNetworkName, opts_network_name, info_network_name, 0},
    {"net-start", cmdNetworkStart, opts_network_start, info_network_start, 0},
    {"net-undefine", cmdNetworkUndefine, opts_network_undefine,
     info_network_undefine, 0},
    {"net-uuid", cmdNetworkUuid, opts_network_uuid, info_network_uuid, 0},
    {NULL, NULL, NULL, NULL, 0}
};
