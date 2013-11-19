/*
 * virsh-network.c: Commands to manage network
 *
 * Copyright (C) 2005, 2007-2013 Red Hat, Inc.
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
#include "virsh-network.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virxml.h"
#include "conf/network_conf.h"

virNetworkPtr
vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                       const char **name, unsigned int flags)
{
    virNetworkPtr network = NULL;
    const char *n = NULL;
    const char *optname = "network";
    virCheckFlags(VSH_BYUUID | VSH_BYNAME, NULL);

    if (!vshCmdHasOption(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flags & VSH_BYUUID) && strlen(n) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network UUID\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (!network && (flags & VSH_BYNAME)) {
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
    {.name = "help",
     .data = N_("autostart a network")
    },
    {.name = "desc",
     .data = N_("Configure a network to be automatically started at boot.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_autostart[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable autostarting")
    },
    {.name = NULL}
};

static bool
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *name;
    int autostart;

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
    {.name = "help",
     .data = N_("create a network from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_create[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML network description")
    },
    {.name = NULL}
};

static bool
cmdNetworkCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
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
    {.name = "help",
     .data = N_("define (but don't start) a network from an XML file")
    },
    {.name = "desc",
     .data = N_("Define a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_define[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML network description")
    },
    {.name = NULL}
};

static bool
cmdNetworkDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
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
    {.name = "help",
     .data = N_("destroy (stop) a network")
    },
    {.name = "desc",
     .data = N_("Forcefully stop a given network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_destroy[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

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
    {.name = "help",
     .data = N_("network information in XML")
    },
    {.name = "desc",
     .data = N_("Output the network information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_dumpxml[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("network information of an inactive domain")
    },
    {.name = NULL}
};

static bool
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    int inactive;

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
    {.name = "help",
     .data = N_("network information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the network")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_info[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = NULL}
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

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virNetworkGetName(network));

    if (virNetworkGetUUIDString(network, uuid) == 0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

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

static int
vshNetworkSorter(const void *a, const void *b)
{
    virNetworkPtr *na = (virNetworkPtr *) a;
    virNetworkPtr *nb = (virNetworkPtr *) b;

    if (*na && !*nb)
        return -1;

    if (!*na)
        return *nb != NULL;

    return vshStrcasecmp(virNetworkGetName(*na),
                      virNetworkGetName(*nb));
}

struct vshNetworkList {
    virNetworkPtr *nets;
    size_t nnets;
};
typedef struct vshNetworkList *vshNetworkListPtr;

static void
vshNetworkListFree(vshNetworkListPtr list)
{
    size_t i;

    if (list && list->nets) {
        for (i = 0; i < list->nnets; i++) {
            if (list->nets[i])
                virNetworkFree(list->nets[i]);
        }
        VIR_FREE(list->nets);
    }
    VIR_FREE(list);
}

static vshNetworkListPtr
vshNetworkListCollect(vshControl *ctl,
                      unsigned int flags)
{
    vshNetworkListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    int ret;
    char **names = NULL;
    virNetworkPtr net;
    bool success = false;
    size_t deleted = 0;
    int persistent;
    int autostart;
    int nActiveNets = 0;
    int nInactiveNets = 0;
    int nAllNets = 0;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllNetworks(ctl->conn,
                                         &list->nets,
                                         flags)) >= 0) {
        list->nnets = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    if (last_error && last_error->code ==  VIR_ERR_INVALID_ARG) {
        /* try the new API again but mask non-guaranteed flags */
        unsigned int newflags = flags & (VIR_CONNECT_LIST_NETWORKS_ACTIVE |
                                         VIR_CONNECT_LIST_NETWORKS_INACTIVE);

        vshResetLibvirtError();
        if ((ret = virConnectListAllNetworks(ctl->conn, &list->nets,
                                             newflags)) >= 0) {
            list->nnets = ret;
            goto filter;
        }
    }

    /* there was an error during the first or second call */
    vshError(ctl, "%s", _("Failed to list networks"));
    goto cleanup;


fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    /* Get the number of active networks */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE)) {
        if ((nActiveNets = virConnectNumOfNetworks(ctl->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of active networks"));
            goto cleanup;
        }
    }

    /* Get the number of inactive networks */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_INACTIVE)) {
        if ((nInactiveNets = virConnectNumOfDefinedNetworks(ctl->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of inactive networks"));
            goto cleanup;
        }
    }

    nAllNets = nActiveNets + nInactiveNets;

    if (nAllNets == 0)
         return list;

    names = vshMalloc(ctl, sizeof(char *) * nAllNets);

    /* Retrieve a list of active network names */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE)) {
        if (virConnectListNetworks(ctl->conn,
                                   names, nActiveNets) < 0) {
            vshError(ctl, "%s", _("Failed to list active networks"));
            goto cleanup;
        }
    }

    /* Add the inactive networks to the end of the name list */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE)) {
        if (virConnectListDefinedNetworks(ctl->conn,
                                          &names[nActiveNets],
                                          nInactiveNets) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive networks"));
            goto cleanup;
        }
    }

    list->nets = vshMalloc(ctl, sizeof(virNetworkPtr) * (nAllNets));
    list->nnets = 0;

    /* get active networks */
    for (i = 0; i < nActiveNets; i++) {
        if (!(net = virNetworkLookupByName(ctl->conn, names[i])))
            continue;
        list->nets[list->nnets++] = net;
    }

    /* get inactive networks */
    for (i = 0; i < nInactiveNets; i++) {
        if (!(net = virNetworkLookupByName(ctl->conn, names[i])))
            continue;
        list->nets[list->nnets++] = net;
    }

    /* truncate networks that weren't found */
    deleted = nAllNets - list->nnets;

filter:
    /* filter list the list if the list was acquired by fallback means */
    for (i = 0; i < list->nnets; i++) {
        net = list->nets[i];

        /* persistence filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT)) {
            if ((persistent = virNetworkIsPersistent(net)) < 0) {
                vshError(ctl, "%s", _("Failed to get network persistence info"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_PERSISTENT) && persistent) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_TRANSIENT) && !persistent)))
                goto remove_entry;
        }

        /* autostart filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART)) {
            if (virNetworkGetAutostart(net, &autostart) < 0) {
                vshError(ctl, "%s", _("Failed to get network autostart state"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_AUTOSTART) && autostart) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART) && !autostart)))
                goto remove_entry;
        }
        /* the pool matched all filters, it may stay */
        continue;

remove_entry:
        /* the pool has to be removed as it failed one of the filters */
        virNetworkFree(list->nets[i]);
        list->nets[i] = NULL;
        deleted++;
    }

finished:
    /* sort the list */
    if (list->nets && list->nnets)
        qsort(list->nets, list->nnets,
              sizeof(*list->nets), vshNetworkSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->nets, list->nnets, deleted);

    success = true;

cleanup:
    for (i = 0; i < nAllNets; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        vshNetworkListFree(list);
        list = NULL;
    }

    return list;
}

/*
 * "net-list" command
 */
static const vshCmdInfo info_network_list[] = {
    {.name = "help",
     .data = N_("list networks")
    },
    {.name = "desc",
     .data = N_("Returns list of networks.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_list[] = {
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive networks")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive & active networks")
    },
    {.name = "persistent",
     .type = VSH_OT_BOOL,
     .help = N_("list persistent networks")
    },
    {.name = "transient",
     .type = VSH_OT_BOOL,
     .help = N_("list transient networks")
    },
    {.name = "autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list networks with autostart enabled")
    },
    {.name = "no-autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list networks with autostart disabled")
    },
    {.name = NULL}
};

static bool
cmdNetworkList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    vshNetworkListPtr list = NULL;
    size_t i;
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool all = vshCommandOptBool(cmd, "all");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    bool transient = vshCommandOptBool(cmd, "transient");
    bool autostart = vshCommandOptBool(cmd, "autostart");
    bool no_autostart = vshCommandOptBool(cmd, "no-autostart");
    unsigned int flags = VIR_CONNECT_LIST_NETWORKS_ACTIVE;

    if (inactive)
        flags = VIR_CONNECT_LIST_NETWORKS_INACTIVE;

    if (all)
        flags = VIR_CONNECT_LIST_NETWORKS_ACTIVE |
                VIR_CONNECT_LIST_NETWORKS_INACTIVE;

    if (persistent)
         flags |= VIR_CONNECT_LIST_NETWORKS_PERSISTENT;

    if (transient)
         flags |= VIR_CONNECT_LIST_NETWORKS_TRANSIENT;

    if (autostart)
         flags |= VIR_CONNECT_LIST_NETWORKS_AUTOSTART;

    if (no_autostart)
         flags |= VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART;

    if (!(list = vshNetworkListCollect(ctl, flags)))
        return false;

    vshPrintExtra(ctl, " %-20s %-10s %-13s %s\n", _("Name"), _("State"),
                  _("Autostart"), _("Persistent"));
    vshPrintExtra(ctl,
                  "----------------------------------------------------------\n");

    for (i = 0; i < list->nnets; i++) {
        virNetworkPtr network = list->nets[i];
        const char *autostartStr;
        int is_autostart = 0;

        if (virNetworkGetAutostart(network, &is_autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = is_autostart ? _("yes") : _("no");

        vshPrint(ctl, " %-20s %-10s %-13s %s\n",
                 virNetworkGetName(network),
                 virNetworkIsActive(network) ? _("active") : _("inactive"),
                 autostartStr,
                 virNetworkIsPersistent(network) ? _("yes") : _("no"));
    }

    vshNetworkListFree(list);
    return true;
}

/*
 * "net-name" command
 */
static const vshCmdInfo info_network_name[] = {
    {.name = "help",
     .data = N_("convert a network UUID to network name")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_name[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network uuid")
    },
    {.name = NULL}
};

static bool
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;

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
    {.name = "help",
     .data = N_("start a (previously defined) inactive network")
    },
    {.name = "desc",
     .data = N_("Start a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_start[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name = NULL;

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
    {.name = "help",
     .data = N_("undefine an inactive network")
    },
    {.name = "desc",
     .data = N_("Undefine the configuration for an inactive network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_undefine[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

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
 * "net-update" command
 */
static const vshCmdInfo info_network_update[] = {
    {.name = "help",
     .data = N_("update parts of an existing network's configuration")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_update[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = "command",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("type of update (add-first, add-last (add), delete, or modify)")
    },
    {.name = "section",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("which section of network configuration to update")
    },
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("name of file containing xml (or, if it starts with '<', the complete "
                "xml element itself) to add/modify, or to be matched for search")
    },
    {.name = "parent-index",
     .type = VSH_OT_INT,
     .help = N_("which parent object to search through")
    },
    {.name = "config",
     .type = VSH_OT_BOOL,
     .help = N_("affect next network startup")
    },
    {.name = "live",
     .type = VSH_OT_BOOL,
     .help = N_("affect running network")
    },
    {.name = "current",
     .type = VSH_OT_BOOL,
     .help = N_("affect current state of network")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virNetworkUpdateCommand)
VIR_ENUM_IMPL(virNetworkUpdateCommand, VIR_NETWORK_UPDATE_COMMAND_LAST,
              "none", "modify", "delete", "add-last", "add-first");

VIR_ENUM_DECL(virNetworkSection)
VIR_ENUM_IMPL(virNetworkSection, VIR_NETWORK_SECTION_LAST,
              "none", "bridge", "domain", "ip", "ip-dhcp-host",
              "ip-dhcp-range", "forward", "forward-interface",
              "forward-pf", "portgroup", "dns-host", "dns-txt",
              "dns-srv");

static bool
cmdNetworkUpdate(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNetworkPtr network;
    const char *commandStr = NULL;
    const char *sectionStr = NULL;
    int command, section, parentIndex = -1;
    const char *xml = NULL;
    char *xmlFromFile = NULL;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    unsigned int flags = 0;
    const char *affected;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "command", &commandStr) < 0)
        goto cleanup;

    if (STREQ(commandStr, "add")) {
        /* "add" is a synonym for "add-last" */
        command = VIR_NETWORK_UPDATE_COMMAND_ADD_LAST;
    } else {
        command = virNetworkUpdateCommandTypeFromString(commandStr);
        if (command <= 0 || command >= VIR_NETWORK_UPDATE_COMMAND_LAST) {
            vshError(ctl, _("unrecognized command name '%s'"), commandStr);
            goto cleanup;
        }
    }

    if (vshCommandOptStringReq(ctl, cmd, "section", &sectionStr) < 0)
        goto cleanup;

    section = virNetworkSectionTypeFromString(sectionStr);
    if (section <= 0 || section >= VIR_NETWORK_SECTION_LAST) {
        vshError(ctl, _("unrecognized section name '%s'"), sectionStr);
        goto cleanup;
    }

    if (vshCommandOptInt(cmd, "parent-index", &parentIndex) < 0) {
        vshError(ctl, "%s", _("malformed parent-index argument"));
        goto cleanup;
    }

    /* The goal is to have a full xml element in the "xml"
     * string. This is provided in the --xml option, either directly
     * (detected by the first character being "<"), or indirectly by
     * supplying a filename (first character isn't "<") that contains
     * the desired xml.
     */

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xml) < 0)
        goto cleanup;

    if (*xml != '<') {
        /* contents of xmldata is actually the name of a file that
         * contains the xml.
         */
        if (virFileReadAll(xml, VSH_MAX_XML_FILE, &xmlFromFile) < 0)
            goto cleanup;
        /* NB: the original xml is just a const char * that points
         * to a string owned by the vshCmd object, and will be freed
         * by vshCommandFree, so it's safe to lose its pointer here.
         */
        xml = xmlFromFile;
    }

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags |= VIR_NETWORK_UPDATE_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
        if (live)
            flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;
    }

    if (virNetworkUpdate(network, command,
                         section, parentIndex, xml, flags) < 0) {
        vshError(ctl, _("Failed to update network %s"),
                 virNetworkGetName(network));
        goto cleanup;
    }

    if (config) {
        if (live)
            affected = _("persistent config and live state");
        else
            affected = _("persistent config");
    } else if (live) {
            affected = _("live state");
    } else if (virNetworkIsActive(network)) {
        affected = _("live state");
    } else {
        affected = _("persistent config");
    }

    vshPrint(ctl, _("Updated network %s %s"),
             virNetworkGetName(network), affected);
    ret = true;
cleanup:
    vshReportError(ctl);
    virNetworkFree(network);
    VIR_FREE(xmlFromFile);
    return ret;
}

/*
 * "net-uuid" command
 */
static const vshCmdInfo info_network_uuid[] = {
    {.name = "help",
     .data = N_("convert a network name to network UUID")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_uuid[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name")
    },
    {.name = NULL}
};

static bool
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];

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
    {.name = "help",
     .data = N_("edit XML configuration for a network")
    },
    {.name = "desc",
     .data = N_("Edit the XML configuration for a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_edit[] = {
    {.name = "network",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network name or uuid")
    },
    {.name = NULL}
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

const vshCmdDef networkCmds[] = {
    {.name = "net-autostart",
     .handler = cmdNetworkAutostart,
     .opts = opts_network_autostart,
     .info = info_network_autostart,
     .flags = 0
    },
    {.name = "net-create",
     .handler = cmdNetworkCreate,
     .opts = opts_network_create,
     .info = info_network_create,
     .flags = 0
    },
    {.name = "net-define",
     .handler = cmdNetworkDefine,
     .opts = opts_network_define,
     .info = info_network_define,
     .flags = 0
    },
    {.name = "net-destroy",
     .handler = cmdNetworkDestroy,
     .opts = opts_network_destroy,
     .info = info_network_destroy,
     .flags = 0
    },
    {.name = "net-dumpxml",
     .handler = cmdNetworkDumpXML,
     .opts = opts_network_dumpxml,
     .info = info_network_dumpxml,
     .flags = 0
    },
    {.name = "net-edit",
     .handler = cmdNetworkEdit,
     .opts = opts_network_edit,
     .info = info_network_edit,
     .flags = 0
    },
    {.name = "net-info",
     .handler = cmdNetworkInfo,
     .opts = opts_network_info,
     .info = info_network_info,
     .flags = 0
    },
    {.name = "net-list",
     .handler = cmdNetworkList,
     .opts = opts_network_list,
     .info = info_network_list,
     .flags = 0
    },
    {.name = "net-name",
     .handler = cmdNetworkName,
     .opts = opts_network_name,
     .info = info_network_name,
     .flags = 0
    },
    {.name = "net-start",
     .handler = cmdNetworkStart,
     .opts = opts_network_start,
     .info = info_network_start,
     .flags = 0
    },
    {.name = "net-undefine",
     .handler = cmdNetworkUndefine,
     .opts = opts_network_undefine,
     .info = info_network_undefine,
     .flags = 0
    },
    {.name = "net-update",
     .handler = cmdNetworkUpdate,
     .opts = opts_network_update,
     .info = info_network_update,
     .flags = 0
    },
    {.name = "net-uuid",
     .handler = cmdNetworkUuid,
     .opts = opts_network_uuid,
     .info = info_network_uuid,
     .flags = 0
    },
    {.name = NULL}
};
