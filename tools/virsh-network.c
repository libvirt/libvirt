/*
 * virsh-network.c: Commands to manage network
 *
 * Copyright (C) 2005, 2007-2019 Red Hat, Inc.
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
#include "virsh-network.h"
#include "virsh-util.h"

#include "internal.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtime.h"
#include "conf/network_conf.h"
#include "vsh-table.h"
#include "virenum.h"

#define VIRSH_COMMON_OPT_NETWORK(_helpstr, cflags) \
    {.name = "network", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = _helpstr, \
     .completer = virshNetworkNameCompleter, \
     .completer_flags = cflags, \
    }

#define VIRSH_COMMON_OPT_NETWORK_FULL(cflags) \
    VIRSH_COMMON_OPT_NETWORK(N_("network name or uuid"), cflags)

#define VIRSH_COMMON_OPT_NETWORK_OT_STRING(_helpstr, cflags) \
    {.name = "network", \
     .type = VSH_OT_STRING, \
     .help = _helpstr, \
     .completer = virshNetworkNameCompleter, \
     .completer_flags = cflags, \
    }

#define VIRSH_COMMON_OPT_NETWORK_OT_STRING_FULL(cflags) \
    VIRSH_COMMON_OPT_NETWORK_OT_STRING(N_("network name or uuid"), cflags)

#define VIRSH_COMMON_OPT_NETWORK_PORT(cflags) \
    {.name = "port", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = N_("port UUID"), \
     .completer = virshNetworkPortUUIDCompleter, \
     .completer_flags = cflags, \
    }


virNetworkPtr
virshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                         const char **name, unsigned int flags)
{
    virNetworkPtr network = NULL;
    const char *n = NULL;
    const char *optname = "network";
    virshControl *priv = ctl->privData;

    virCheckFlags(VIRSH_BYUUID | VIRSH_BYNAME, NULL);

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flags & VIRSH_BYUUID) && strlen(n) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network UUID\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByUUIDString(priv->conn, n);
    }
    /* try it by NAME */
    if (!network && (flags & VIRSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network NAME\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByName(priv->conn, n);
    }

    if (!network)
        vshError(ctl, _("failed to get network '%1$s'"), n);

    return network;
}


virNetworkPortPtr
virshCommandOptNetworkPort(vshControl *ctl, const vshCmd *cmd,
                           virNetworkPtr net,
                           const char **name)
{
    virNetworkPortPtr port = NULL;
    const char *n = NULL;
    const char *optname = "port";

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network UUID\n",
             cmd->def->name, optname);
    port = virNetworkPortLookupByUUIDString(net, n);

    if (!port)
        vshError(ctl, _("failed to get network port '%1$s'"), n);

    return port;
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
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_PERSISTENT),
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable autostarting")
    },
    {.name = NULL}
};

static bool
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    const char *name;
    int autostart;

    if (!(network = virshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virNetworkSetAutostart(network, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark network %1$s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark network %1$s as autostarted"), name);
        return false;
    }

    if (autostart)
        vshPrintExtra(ctl, _("Network %1$s marked as autostarted\n"), name);
    else
        vshPrintExtra(ctl, _("Network %1$s unmarked as autostarted\n"), name);

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
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML network description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdNetworkCreate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_NETWORK_CREATE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (flags)
        network = virNetworkCreateXMLFlags(priv->conn, buffer, flags);
    else
        network = virNetworkCreateXML(priv->conn, buffer);

    if (!network) {
        vshError(ctl, _("Failed to create network from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Network %1$s created from %2$s\n"),
                  virNetworkGetName(network), from);
    return true;
}

/*
 * "net-define" command
 */
static const vshCmdInfo info_network_define[] = {
    {.name = "help",
     .data = N_("define an inactive persistent virtual network or modify "
                "an existing persistent one from an XML file")
    },
    {.name = "desc",
     .data = N_("Define or modify a persistent virtual network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_define[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML network description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdNetworkDefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_NETWORK_DEFINE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (flags)
        network = virNetworkDefineXMLFlags(priv->conn, buffer, flags);
    else
        network = virNetworkDefineXML(priv->conn, buffer);

    if (!network) {
        vshError(ctl, _("Failed to define network from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Network %1$s defined from %2$s\n"),
                  virNetworkGetName(network), from);
    return true;
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
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    {.name = NULL}
};

static bool
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    bool ret = true;
    const char *name;

    if (!(network = virshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkDestroy(network) == 0) {
        vshPrintExtra(ctl, _("Network %1$s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy network %1$s"), name);
        ret = false;
    }

    return ret;
}

/*
 * "net-desc" command
 */
static const vshCmdInfo info_network_desc[] = {
    {.name = "help",
     .data = N_("show or set network's description or title")
    },
    {.name = "desc",
     .data = N_("Allows setting or modifying the description or title of a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_desc[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    VIRSH_COMMON_OPT_LIVE(N_("modify/get running state")),
    VIRSH_COMMON_OPT_CONFIG(N_("modify/get persistent configuration")),
    VIRSH_COMMON_OPT_CURRENT(N_("modify/get current state configuration")),
    {.name = "title",
     .type = VSH_OT_BOOL,
     .help = N_("modify/get the title instead of description")
    },
    {.name = "edit",
     .type = VSH_OT_BOOL,
     .help = N_("open an editor to modify the description")
    },
    {.name = "new-desc",
     .type = VSH_OT_ARGV,
     .help = N_("message")
    },
    {.name = NULL}
};

/* extract description or title from network xml */
static char *
virshGetNetworkDescription(vshControl *ctl, virNetworkPtr net,
                           bool title, unsigned int flags,
                           unsigned int queryflags)
{
    char *desc = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int type;

    if (title)
        type = VIR_NETWORK_METADATA_TITLE;
    else
        type = VIR_NETWORK_METADATA_DESCRIPTION;

    if ((desc = virNetworkGetMetadata(net, type, NULL, flags))) {
        return desc;
    } else {
        int errCode = virGetLastErrorCode();

        if (errCode == VIR_ERR_NO_NETWORK_METADATA) {
            desc = g_strdup("");
            vshResetLibvirtError();
            return desc;
        }

        if (errCode != VIR_ERR_NO_SUPPORT)
            return desc;
    }

    /* fall back to xml */
    if (virshNetworkGetXMLFromNet(ctl, net, queryflags, &doc, &ctxt) < 0)
        return NULL;

    if (title)
        desc = virXPathString("string(./title[1])", ctxt);
    else
        desc = virXPathString("string(./description[1])", ctxt);

    if (!desc)
        desc = g_strdup("");

    return desc;
}

static bool
cmdNetworkDesc(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) net = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool title = vshCommandOptBool(cmd, "title");
    bool edit = vshCommandOptBool(cmd, "edit");

    int type;
    g_autofree char *descArg = NULL;
    const vshCmdOpt *opt = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = VIR_NETWORK_UPDATE_AFFECT_CURRENT;
    unsigned int queryflags = 0;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config) {
        flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
        queryflags |= VIR_NETWORK_XML_INACTIVE;
    }
    if (live)
        flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;

    if (!(net = virshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if (title)
        type = VIR_NETWORK_METADATA_TITLE;
    else
        type = VIR_NETWORK_METADATA_DESCRIPTION;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        virBufferAsprintf(&buf, "%s ", opt->data);

    virBufferTrim(&buf, " ");

    descArg = virBufferContentAndReset(&buf);

    if (edit || descArg) {
        g_autofree char *descNet = NULL;
        g_autofree char *descNew = NULL;

        if (!(descNet = virshGetNetworkDescription(ctl, net, title, flags, queryflags)))
            return false;

        if (!descArg)
            descArg = g_strdup(descNet);

        if (edit) {
            g_autoptr(vshTempFile) tmp = NULL;
            g_autofree char *desc_edited = NULL;
            char *tmpstr;

            /* Create and open the temporary file. */
            if (!(tmp = vshEditWriteToTempFile(ctl, descArg)))
                return false;

            /* Start the editor. */
            if (vshEditFile(ctl, tmp) == -1)
                return false;

            /* Read back the edited file. */
            if (!(desc_edited = vshEditReadBackFile(ctl, tmp)))
                return false;

            /* strip a possible newline at the end of file; some
             * editors enforce a newline, this makes editing the title
             * more convenient */
            if (title &&
                (tmpstr = strrchr(desc_edited, '\n')) &&
                *(tmpstr+1) == '\0')
                *tmpstr = '\0';

            /* Compare original XML with edited.  Has it changed at all? */
            if (STREQ(descNet, desc_edited)) {
                if (title)
                    vshPrintExtra(ctl, "%s", _("Network title not changed\n"));
                else
                    vshPrintExtra(ctl, "%s", _("Network description not changed\n"));

                return true;
            }

            descNew = g_steal_pointer(&desc_edited);
        } else {
            descNew = g_steal_pointer(&descArg);
        }

        if (virNetworkSetMetadata(net, type, descNew, NULL, NULL, flags) < 0) {
            if (title)
                vshError(ctl, "%s", _("Failed to set new network title"));
            else
                vshError(ctl, "%s", _("Failed to set new network description"));

            return false;
        }

        if (title)
            vshPrintExtra(ctl, "%s", _("Network title updated successfully"));
        else
            vshPrintExtra(ctl, "%s", _("Network description updated successfully"));

    } else {
        g_autofree char *desc = virshGetNetworkDescription(ctl, net, title, flags, queryflags);
        if (!desc)
            return false;

        if (strlen(desc) > 0) {
            vshPrint(ctl, "%s", desc);
        } else {
            if (title)
                vshPrintExtra(ctl, _("No title for network: %1$s"), virNetworkGetName(net));
            else
                vshPrintExtra(ctl, _("No description for network: %1$s"), virNetworkGetName(net));
        }
    }

    return true;
}

/*
 * "net-metadata" command
 */
static const vshCmdInfo info_network_metadata[] = {
    {.name = "help",
     .data = N_("show or set network's custom XML metadata")
    },
    {.name = "desc",
     .data = N_("Shows or modifies the XML metadata of a network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_metadata[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    {.name = "uri",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("URI of the namespace")
    },
    VIRSH_COMMON_OPT_LIVE(N_("modify/get running state")),
    VIRSH_COMMON_OPT_CONFIG(N_("modify/get persistent configuration")),
    VIRSH_COMMON_OPT_CURRENT(N_("modify/get current state configuration")),
    {.name = "edit",
     .type = VSH_OT_BOOL,
     .help = N_("use an editor to change the metadata")
    },
    {.name = "key",
     .type = VSH_OT_STRING,
     .help = N_("key to be used as a namespace identifier"),
    },
    {.name = "set",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("new metadata to set"),
    },
    {.name = "remove",
     .type = VSH_OT_BOOL,
     .help = N_("remove the metadata corresponding to an uri")
    },
    {.name = NULL}
};

/* helper to add new metadata using the --edit option */
static char *
virshNetworkGetEditMetadata(vshControl *ctl G_GNUC_UNUSED,
                            virNetworkPtr net,
                            const char *uri,
                            unsigned int flags)
{
    char *ret;

    if (!(ret = virNetworkGetMetadata(net, VIR_NETWORK_METADATA_ELEMENT,
                                      uri, flags))) {
        vshResetLibvirtError();
        ret = g_strdup("\n");
    }

    return ret;
}

static bool
cmdNetworkMetadata(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) net = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool edit = vshCommandOptBool(cmd, "edit");
    bool rem = vshCommandOptBool(cmd, "remove");
    const char *set = NULL;
    const char *uri = NULL;
    const char *key = NULL;
    unsigned int flags = VIR_NETWORK_UPDATE_AFFECT_CURRENT;
    bool ret = false;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    VSH_EXCLUSIVE_OPTIONS("edit", "set");
    VSH_EXCLUSIVE_OPTIONS("remove", "set");
    VSH_EXCLUSIVE_OPTIONS("remove", "edit");

    if (config)
        flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
    if (live)
        flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;

    if (!(net = virshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "uri", &uri) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "key", &key) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "set", &set) < 0)
        return false;

    if ((set || edit) && !key) {
        vshError(ctl, "%s",
                 _("namespace key is required when modifying metadata"));
        return false;
    }

    if (set || rem) {
        if (virNetworkSetMetadata(net, VIR_NETWORK_METADATA_ELEMENT,
                                  set, key, uri, flags))
            return false;

        if (rem)
            vshPrintExtra(ctl, "%s\n", _("Metadata removed"));
        else
            vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else if (edit) {
#define EDIT_GET_XML \
        virshNetworkGetEditMetadata(ctl, net, uri, flags)
#define EDIT_NOT_CHANGED \
        do { \
            vshPrintExtra(ctl, "%s", _("Metadata not changed")); \
            ret = true; \
            goto edit_cleanup; \
        } while (0)

#define EDIT_DEFINE \
        (virNetworkSetMetadata(net, VIR_NETWORK_METADATA_ELEMENT, doc_edited, \
                               key, uri, flags) == 0)
#include "virsh-edit.c"

        vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else {
        g_autofree char *data = NULL;

        /* get */
        if (!(data = virNetworkGetMetadata(net, VIR_NETWORK_METADATA_ELEMENT,
                                           uri, flags)))
            return false;

        vshPrint(ctl, "%s\n", data);
    }

    ret = true;

 cleanup:
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
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("show inactive defined XML")
    },
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_NETWORK_XML_INACTIVE;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virNetworkGetXMLDesc(network, flags)))
        return false;

    return virshDumpXML(ctl, xml, "network", xpath, wrap);
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
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    {.name = NULL}
};

static bool
cmdNetworkInfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int autostart;
    int persistent = -1;
    int active = -1;
    g_autofree char *bridge = NULL;

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
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

    return true;
}

static int
virshNetworkSorter(const void *a, const void *b)
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

struct virshNetworkList {
    virNetworkPtr *nets;
    size_t nnets;
};

static void
virshNetworkListFree(struct virshNetworkList *list)
{
    size_t i;

    if (list && list->nets) {
        for (i = 0; i < list->nnets; i++) {
            virshNetworkFree(list->nets[i]);
        }
        g_free(list->nets);
    }
    g_free(list);
}

static struct virshNetworkList *
virshNetworkListCollect(vshControl *ctl,
                        unsigned int flags)
{
    struct virshNetworkList *list = g_new0(struct virshNetworkList, 1);
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
    virshControl *priv = ctl->privData;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllNetworks(priv->conn,
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
        if ((ret = virConnectListAllNetworks(priv->conn, &list->nets,
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
        if ((nActiveNets = virConnectNumOfNetworks(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of active networks"));
            goto cleanup;
        }
    }

    /* Get the number of inactive networks */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_INACTIVE)) {
        if ((nInactiveNets = virConnectNumOfDefinedNetworks(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to get the number of inactive networks"));
            goto cleanup;
        }
    }

    nAllNets = nActiveNets + nInactiveNets;

    if (nAllNets == 0)
         return list;

    names = g_new0(char *, nAllNets);

    /* Retrieve a list of active network names */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE)) {
        if (virConnectListNetworks(priv->conn,
                                   names, nActiveNets) < 0) {
            vshError(ctl, "%s", _("Failed to list active networks"));
            goto cleanup;
        }
    }

    /* Add the inactive networks to the end of the name list */
    if (!VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE)) {
        if (virConnectListDefinedNetworks(priv->conn,
                                          &names[nActiveNets],
                                          nInactiveNets) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive networks"));
            goto cleanup;
        }
    }

    list->nets = g_new0(virNetworkPtr, nAllNets);
    list->nnets = 0;

    /* get active networks */
    for (i = 0; i < nActiveNets; i++) {
        if (!(net = virNetworkLookupByName(priv->conn, names[i])))
            continue;
        list->nets[list->nnets++] = net;
    }

    /* get inactive networks */
    for (i = 0; i < nInactiveNets; i++) {
        if (!(net = virNetworkLookupByName(priv->conn, names[i])))
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
        g_clear_pointer(&list->nets[i], virshNetworkFree);
        deleted++;
    }

 finished:
    /* sort the list */
    if (list->nets && list->nnets)
        qsort(list->nets, list->nnets,
              sizeof(*list->nets), virshNetworkSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->nets, list->nnets, deleted);

    success = true;

 cleanup:
    for (i = 0; i < nAllNets; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        g_clear_pointer(&list, virshNetworkListFree);
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
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("list uuid's only")
    },
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list network names only")
    },
    {.name = "table",
     .type = VSH_OT_BOOL,
     .help = N_("list table (default)")
    },
    {.name = "title",
     .type = VSH_OT_BOOL,
     .help = N_("show network title")
    },
    {.name = NULL}
};

#define FILTER(NAME, FLAG) \
    if (vshCommandOptBool(cmd, NAME)) \
        flags |= (FLAG)
static bool
cmdNetworkList(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    struct virshNetworkList *list = NULL;
    size_t i;
    bool ret = false;
    bool optName = vshCommandOptBool(cmd, "name");
    bool optTitle = vshCommandOptBool(cmd, "title");
    bool optTable = vshCommandOptBool(cmd, "table");
    bool optUUID = vshCommandOptBool(cmd, "uuid");
    char uuid[VIR_UUID_STRING_BUFLEN];
    unsigned int flags = VIR_CONNECT_LIST_NETWORKS_ACTIVE;
    g_autoptr(vshTable) table = NULL;

    if (vshCommandOptBool(cmd, "inactive"))
        flags = VIR_CONNECT_LIST_NETWORKS_INACTIVE;

    if (vshCommandOptBool(cmd, "all"))
        flags = VIR_CONNECT_LIST_NETWORKS_ACTIVE |
                VIR_CONNECT_LIST_NETWORKS_INACTIVE;

    FILTER("persistent", VIR_CONNECT_LIST_NETWORKS_PERSISTENT);
    FILTER("transient", VIR_CONNECT_LIST_NETWORKS_TRANSIENT);

    FILTER("autostart", VIR_CONNECT_LIST_NETWORKS_AUTOSTART);
    FILTER("no-autostart", VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART);

    if (optTable + optName + optUUID > 1) {
        vshError(ctl, "%s",
                 _("Only one argument from --table, --name and --uuid may be specified."));
        return false;
    }

    if (!optUUID && !optName)
        optTable = true;

    if (!(list = virshNetworkListCollect(ctl, flags)))
        return false;

    if (optTable) {
        if (optTitle)
            table = vshTableNew(_("Name"), _("State"), _("Autostart"),
                                _("Persistent"), _("Title"), NULL);
        else
            table = vshTableNew(_("Name"), _("State"), _("Autostart"),
                                _("Persistent"), NULL);
        if (!table)
            goto cleanup;
    }

    for (i = 0; i < list->nnets; i++) {
        virNetworkPtr network = list->nets[i];
        const char *autostartStr;
        int is_autostart = 0;

        if (optTable) {
            if (virNetworkGetAutostart(network, &is_autostart) < 0)
                autostartStr = _("no autostart");
            else
                autostartStr = is_autostart ? _("yes") : _("no");

            if (optTitle) {
                g_autofree char *title = NULL;

                if (!(title = virshGetNetworkDescription(ctl, network, true, 0, 0)))
                    goto cleanup;
                if (vshTableRowAppend(table,
                            virNetworkGetName(network),
                            virNetworkIsActive(network) ?
                            _("active") : _("inactive"),
                            autostartStr,
                            virNetworkIsPersistent(network) ?
                            _("yes") : _("no"),
                            title,
                            NULL) < 0)
                    goto cleanup;

            } else {
                if (vshTableRowAppend(table,
                            virNetworkGetName(network),
                            virNetworkIsActive(network) ?
                            _("active") : _("inactive"),
                            autostartStr,
                            virNetworkIsPersistent(network) ?
                            _("yes") : _("no"),
                            NULL) < 0)
                    goto cleanup;

            }

        } else if (optUUID) {

            if (virNetworkGetUUIDString(network, uuid) < 0) {
                vshError(ctl, "%s", _("Failed to get network's UUID"));
                goto cleanup;
            }
            vshPrint(ctl, "%s\n", uuid);
        } else if (optName) {
            vshPrint(ctl, "%s\n", virNetworkGetName(network));
        }
    }

    if (optTable)
        vshTablePrintToStdout(table, ctl);

    ret = true;
 cleanup:
    virshNetworkListFree(list);
    return ret;
}
#undef FILTER

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
     .completer = virshNetworkUUIDCompleter,
     .help = N_("network uuid")
    },
    {.name = NULL}
};

static bool
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;

    if (!(network = virshCommandOptNetworkBy(ctl, cmd, NULL,
                                             VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virNetworkGetName(network));
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
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_INACTIVE),
    {.name = NULL}
};

static bool
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    bool ret = true;
    const char *name = NULL;

    if (!(network = virshCommandOptNetwork(ctl, cmd, &name)))
         return false;

    if (virNetworkCreate(network) == 0) {
        vshPrintExtra(ctl, _("Network %1$s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start network %1$s"), name);
        ret = false;
    }
    return ret;
}

/*
 * "net-undefine" command
 */
static const vshCmdInfo info_network_undefine[] = {
    {.name = "help",
     .data = N_("undefine a persistent network")
    },
    {.name = "desc",
     .data = N_("Undefine the configuration for a persistent network.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_undefine[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_PERSISTENT),
    {.name = NULL}
};

static bool
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    bool ret = true;
    const char *name;

    if (!(network = virshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkUndefine(network) == 0) {
        vshPrintExtra(ctl, _("Network %1$s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network %1$s"), name);
        ret = false;
    }

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
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    {.name = "command",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshNetworkUpdateCommandCompleter,
     .help = N_("type of update (add-first, add-last (add), delete, or modify)")
    },
    {.name = "section",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshNetworkUpdateSectionCompleter,
     .help = N_("which section of network configuration to update")
    },
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompletePathLocalExisting,
     .help = N_("name of file containing xml (or, if it starts with '<', the complete "
                "xml element itself) to add/modify, or to be matched for search")
    },
    {.name = "parent-index",
     .type = VSH_OT_INT,
     .help = N_("which parent object to search through")
    },
    VIRSH_COMMON_OPT_CONFIG(N_("affect next network startup")),
    VIRSH_COMMON_OPT_LIVE(N_("affect running network")),
    VIRSH_COMMON_OPT_CURRENT(N_("affect current state of network")),
    {.name = NULL}
};

VIR_ENUM_IMPL(virshNetworkUpdateCommand,
              VIR_NETWORK_UPDATE_COMMAND_LAST,
              "none", "modify", "delete", "add-last", "add-first");

VIR_ENUM_IMPL(virshNetworkSection,
              VIR_NETWORK_SECTION_LAST,
              "none", "bridge", "domain", "ip", "ip-dhcp-host",
              "ip-dhcp-range", "forward", "forward-interface",
              "forward-pf", "portgroup", "dns-host", "dns-txt",
              "dns-srv");

static bool
cmdNetworkUpdate(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    g_autoptr(virshNetwork) network = NULL;
    const char *commandStr = NULL;
    const char *sectionStr = NULL;
    int command, section, parentIndex = -1;
    const char *xml = NULL;
    g_autofree char *xmlFromFile = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    unsigned int flags = VIR_NETWORK_UPDATE_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS("current", "live");
    VSH_EXCLUSIVE_OPTIONS("current", "config");

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "command", &commandStr) < 0)
        goto cleanup;

    if (STREQ(commandStr, "add")) {
        /* "add" is a synonym for "add-last" */
        command = VIR_NETWORK_UPDATE_COMMAND_ADD_LAST;
    } else {
        command = virshNetworkUpdateCommandTypeFromString(commandStr);
        if (command <= 0) {
            vshError(ctl, _("unrecognized command name '%1$s'"), commandStr);
            goto cleanup;
        }
    }

    if (vshCommandOptStringReq(ctl, cmd, "section", &sectionStr) < 0)
        goto cleanup;

    section = virshNetworkSectionTypeFromString(sectionStr);
    if (section <= 0) {
        vshError(ctl, _("unrecognized section name '%1$s'"), sectionStr);
        goto cleanup;
    }

    if (vshCommandOptInt(ctl, cmd, "parent-index", &parentIndex) < 0)
        goto cleanup;

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

    if (config)
        flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
    if (live)
        flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;

    if (virNetworkUpdate(network, command,
                         section, parentIndex, xml, flags) < 0) {
        vshError(ctl, _("Failed to update network %1$s"),
                 virNetworkGetName(network));
        goto cleanup;
    }

    if (config) {
        if (live)
            vshPrintExtra(ctl, _("Updated network %1$s persistent config and live state"),
                          virNetworkGetName(network));
        else
            vshPrintExtra(ctl, _("Updated network %1$s persistent config"),
                          virNetworkGetName(network));
    } else if (live) {
        vshPrintExtra(ctl, _("Updated network %1$s live state"),
                      virNetworkGetName(network));
    } else if (virNetworkIsActive(network)) {
        vshPrintExtra(ctl, _("Updated network %1$s live state"),
                      virNetworkGetName(network));
    } else {
        vshPrintExtra(ctl, _("Updated network %1$s persistent config"),
                      virNetworkGetName(network));
    }

    ret = true;
 cleanup:
    vshReportError(ctl);
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
    VIRSH_COMMON_OPT_NETWORK(N_("network name"), 0),
    {.name = NULL}
};

static bool
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!(network = virshCommandOptNetworkBy(ctl, cmd, NULL,
                                             VIRSH_BYNAME)))
        return false;

    if (virNetworkGetUUIDString(network, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get network UUID"));

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
    VIRSH_COMMON_OPT_NETWORK_FULL(0),
    {.name = NULL}
};

static char *virshNetworkGetXMLDesc(virNetworkPtr network)
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
    g_autoptr(virshNetwork) network = NULL;
    g_autoptr(virshNetwork) network_edited = NULL;
    virshControl *priv = ctl->privData;

    network = virshCommandOptNetwork(ctl, cmd, NULL);
    if (network == NULL)
        goto cleanup;

#define EDIT_GET_XML virshNetworkGetXMLDesc(network)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Network %1$s XML configuration not changed.\n"), \
                      virNetworkGetName(network)); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (network_edited = virNetworkDefineXML(priv->conn, doc_edited))
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("Network %1$s XML configuration edited.\n"),
                  virNetworkGetName(network_edited));

    ret = true;

 cleanup:
    return ret;
}


/*
 * "net-event" command
 */
VIR_ENUM_DECL(virshNetworkEvent);
VIR_ENUM_IMPL(virshNetworkEvent,
              VIR_NETWORK_EVENT_LAST,
              N_("Defined"),
              N_("Undefined"),
              N_("Started"),
              N_("Stopped"));

static const char *
virshNetworkEventToString(int event)
{
    const char *str = virshNetworkEventTypeToString(event);
    return str ? _(str) : _("unknown");
}

struct virshNetEventData {
    vshControl *ctl;
    bool loop;
    bool timestamp;
    int count;
    virshNetworkEventCallback *cb;
};
typedef struct virshNetEventData virshNetEventData;

VIR_ENUM_DECL(virshNetworkEventId);
VIR_ENUM_IMPL(virshNetworkEventId,
              VIR_NETWORK_EVENT_ID_LAST,
              "lifecycle",
              "metadata-change");

static void
vshEventLifecyclePrint(virConnectPtr conn G_GNUC_UNUSED,
                       virNetworkPtr net,
                       int event,
                       int detail G_GNUC_UNUSED,
                       void *opaque)
{
    virshNetEventData *data = opaque;

    if (!data->loop && data->count)
        return;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%1$s: event 'lifecycle' for network %2$s: %3$s\n"),
                 timestamp,
                 virNetworkGetName(net), virshNetworkEventToString(event));
    } else {
        vshPrint(data->ctl, _("event 'lifecycle' for network %1$s: %2$s\n"),
                 virNetworkGetName(net), virshNetworkEventToString(event));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

VIR_ENUM_DECL(virshNetworkEventMetadataChangeType);
VIR_ENUM_IMPL(virshNetworkEventMetadataChangeType,
              VIR_NETWORK_METADATA_LAST,
              N_("description"),
              N_("title"),
              N_("element"));

#define UNKNOWNSTR(str) (str ? str : N_("unsupported value"))

static void
vshEventMetadataChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                            virNetworkPtr net,
                            int type,
                            const char *nsuri,
                            void *opaque)
{
    virshNetEventData *data = opaque;

    if (!data->loop && data->count)
        return;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%1$s: event 'metadata-change' for network %2$s: type %3$s, uri %4$s\n"),
                 timestamp, virNetworkGetName(net),
                 UNKNOWNSTR(virshNetworkEventMetadataChangeTypeTypeToString(type)), NULLSTR(nsuri));
    } else {
        vshPrint(data->ctl, _("event 'metadata-change' for network %1$s: type %2$s, uri %3$s\n"),
                 virNetworkGetName(net),
                 UNKNOWNSTR(virshNetworkEventMetadataChangeTypeTypeToString(type)), NULLSTR(nsuri));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

virshNetworkEventCallback virshNetworkEventCallbacks[] = {
    { "lifecycle",
      VIR_NETWORK_EVENT_CALLBACK(vshEventLifecyclePrint), },
    { "metadata-change",
      VIR_NETWORK_EVENT_CALLBACK(vshEventMetadataChangePrint), },
};
G_STATIC_ASSERT(VIR_NETWORK_EVENT_ID_LAST == G_N_ELEMENTS(virshNetworkEventCallbacks));

static const vshCmdInfo info_network_event[] = {
    {.name = "help",
     .data = N_("Network Events")
    },
    {.name = "desc",
     .data = N_("List event types, or wait for network events to occur")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_event[] = {
    VIRSH_COMMON_OPT_NETWORK_OT_STRING(N_("filter by network name or uuid"), 0),
    {.name = "event",
     .type = VSH_OT_STRING,
     .completer = virshNetworkEventNameCompleter,
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
cmdNetworkEvent(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) net = NULL;
    bool ret = false;
    int eventId = -1;
    int timeout = 0;
    virshNetEventData data;
    const char *eventName = NULL;
    int event;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "list")) {
        size_t i;

        for (i = 0; i < VIR_NETWORK_EVENT_ID_LAST; i++)
            vshPrint(ctl, "%s\n", virshNetworkEventCallbacks[i].name);
        return true;
    }

    if (vshCommandOptStringReq(ctl, cmd, "event", &eventName) < 0)
        return false;
    if (!eventName) {
        vshError(ctl, "%s", _("either --list or --event <type> is required"));
        return false;
    }
    for (event = 0; event < VIR_NETWORK_EVENT_ID_LAST; event++)
        if (STREQ(eventName, virshNetworkEventCallbacks[event].name))
            break;
    if (event == VIR_NETWORK_EVENT_ID_LAST) {
        vshError(ctl, _("unknown event type %1$s"), eventName);
        return false;
    }

    data.ctl = ctl;
    data.loop = vshCommandOptBool(cmd, "loop");
    data.timestamp = vshCommandOptBool(cmd, "timestamp");
    data.count = 0;
    data.cb = &virshNetworkEventCallbacks[event];
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (vshCommandOptBool(cmd, "network"))
        net = virshCommandOptNetwork(ctl, cmd, NULL);
    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    if ((eventId = virConnectNetworkEventRegisterAny(priv->conn, net, event,
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
    vshPrint(ctl, _("events received: %1$d\n"), data.count);
    if (data.count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (eventId >= 0 &&
        virConnectNetworkEventDeregisterAny(priv->conn, eventId) < 0)
        ret = false;
    return ret;
}


/*
 * "net-dhcp-leases" command
 */
static const vshCmdInfo info_network_dhcp_leases[] = {
    {.name = "help",
     .data = N_("print lease info for a given network")
    },
    {.name = "desc",
     .data = N_("Print lease info for a given network")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_dhcp_leases[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    {.name = "mac",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .help = N_("MAC address"),
     .completer = virshNetworkDhcpMacCompleter,
    },
    {.name = NULL}
};

static int
virshNetworkDHCPLeaseSorter(const void *a, const void *b)
{
    virNetworkDHCPLeasePtr *lease1 = (virNetworkDHCPLeasePtr *) a;
    virNetworkDHCPLeasePtr *lease2 = (virNetworkDHCPLeasePtr *) b;

    if (*lease1 && !*lease2)
        return -1;

    if (!*lease1)
        return *lease2 != NULL;

    return vshStrcasecmp((*lease1)->mac, (*lease2)->mac);
}

static bool
cmdNetworkDHCPLeases(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    const char *mac = NULL;
    virNetworkDHCPLeasePtr *leases = NULL;
    int nleases = 0;
    bool ret = false;
    size_t i;
    unsigned int flags = 0;
    g_autoptr(virshNetwork) network = NULL;
    g_autoptr(vshTable) table = NULL;

    if (vshCommandOptStringReq(ctl, cmd, "mac", &mac) < 0)
        return false;

    if (!(network = virshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if ((nleases = virNetworkGetDHCPLeases(network, mac, &leases, flags)) < 0) {
        vshError(ctl, _("Failed to get leases info for %1$s"), name);
        goto cleanup;
    }

    /* Sort the list according to MAC Address/IAID */
    qsort(leases, nleases, sizeof(*leases), virshNetworkDHCPLeaseSorter);

    table = vshTableNew(_("Expiry Time"), _("MAC address"), _("Protocol"),
                        _("IP address"), _("Hostname"), _("Client ID or DUID"),
                        NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < nleases; i++) {
        const char *typestr = NULL;
        g_autofree char *cidr_format = NULL;
        virNetworkDHCPLeasePtr lease = leases[i];
        g_autoptr(GDateTime) then = g_date_time_new_from_unix_local(lease->expirytime);
        g_autofree char *thenstr = NULL;

        thenstr = g_date_time_format(then, "%Y-%m-%d %H:%M:%S");

        if (lease->type == VIR_IP_ADDR_TYPE_IPV4)
            typestr = "ipv4";
        else if (lease->type == VIR_IP_ADDR_TYPE_IPV6)
            typestr = "ipv6";

        cidr_format = g_strdup_printf("%s/%d", lease->ipaddr, lease->prefix);

        if (vshTableRowAppend(table,
                              thenstr,
                              NULLSTR_MINUS(lease->mac),
                              NULLSTR_MINUS(typestr),
                              NULLSTR_MINUS(cidr_format),
                              NULLSTR_MINUS(lease->hostname),
                              NULLSTR_MINUS(lease->clientid),
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    if (leases) {
        for (i = 0; i < nleases; i++)
            virNetworkDHCPLeaseFree(leases[i]);
        VIR_FREE(leases);
    }
    return ret;
}

/*
 * "net-port-create" command
 */
static const vshCmdInfo info_network_port_create[] = {
    {.name = "help",
     .data = N_("create a network port from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a network port.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_port_create[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML network port description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdNetworkPortCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPortPtr port = NULL;
    const char *from = NULL;
    bool ret = false;
    g_autofree char *buffer = NULL;
    g_autoptr(virshNetwork) network = NULL;
    unsigned int flags = 0;

    network = virshCommandOptNetwork(ctl, cmd, NULL);
    if (network == NULL)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_NETWORK_PORT_CREATE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    port = virNetworkPortCreateXML(network, buffer, flags);

    if (port != NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virNetworkPortGetUUIDString(port, uuidstr);
        vshPrintExtra(ctl, _("Network port %1$s created from %2$s\n"),
                      uuidstr, from);
    } else {
        vshError(ctl, _("Failed to create network from %1$s"), from);
        goto cleanup;
    }

    ret = true;
 cleanup:
    if (port)
        virNetworkPortFree(port);
    return ret;
}

/*
 * "net-port-dumpxml" command
 */
static const vshCmdInfo info_network_port_dumpxml[] = {
    {.name = "help",
     .data = N_("network port information in XML")
    },
    {.name = "desc",
     .data = N_("Output the network port information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_port_dumpxml[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    VIRSH_COMMON_OPT_NETWORK_PORT(0),
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdNetworkPortDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    virNetworkPortPtr port = NULL;
    bool ret = true;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
        goto cleanup;

    if (!(port = virshCommandOptNetworkPort(ctl, cmd, network, NULL)))
        goto cleanup;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virNetworkPortGetXMLDesc(port, flags)))
        goto cleanup;

    ret = virshDumpXML(ctl, xml, "network-port", xpath, wrap);

 cleanup:
    if (port)
        virNetworkPortFree(port);
    return ret;
}


/*
 * "net-port-delete" command
 */
static const vshCmdInfo info_network_port_delete[] = {
    {.name = "help",
     .data = N_("delete the specified network port")
    },
    {.name = "desc",
     .data = N_("Delete the specified network port.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_port_delete[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    VIRSH_COMMON_OPT_NETWORK_PORT(0),
    {.name = NULL}
};

static bool
cmdNetworkPortDelete(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNetwork) network = NULL;
    virNetworkPortPtr port = NULL;
    bool ret = true;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
        goto cleanup;

    if (!(port = virshCommandOptNetworkPort(ctl, cmd, network, NULL)))
        goto cleanup;

    if (virNetworkPortGetUUIDString(port, uuidstr) < 0)
        goto cleanup;

    if (virNetworkPortDelete(port, 0) < 0) {
        vshError(ctl, _("Failed to delete network port %1$s"), uuidstr);
        goto cleanup;
    } else {
        vshPrintExtra(ctl, _("Network port %1$s deleted\n"), uuidstr);
    }

    ret = true;
 cleanup:
    if (port)
        virNetworkPortFree(port);
    return ret;
}


static int
virshNetworkPortSorter(const void *a, const void *b)
{
    virNetworkPortPtr *na = (virNetworkPortPtr *) a;
    virNetworkPortPtr *nb = (virNetworkPortPtr *) b;
    unsigned char uuida[VIR_UUID_BUFLEN];
    unsigned char uuidb[VIR_UUID_BUFLEN];

    if (*na && !*nb)
        return -1;

    if (!*na)
        return *nb != NULL;

    if (virNetworkPortGetUUID(*na, uuida) < 0 ||
        virNetworkPortGetUUID(*nb, uuidb) < 0)
        return -1;

    return memcmp(uuida, uuidb, VIR_UUID_BUFLEN);
}

struct virshNetworkPortList {
    virNetworkPortPtr *ports;
    size_t nports;
};

static void
virshNetworkPortListFree(struct virshNetworkPortList *list)
{
    size_t i;

    if (list && list->ports) {
        for (i = 0; i < list->nports; i++) {
            if (list->ports[i])
                virNetworkPortFree(list->ports[i]);
        }
        g_free(list->ports);
    }
    g_free(list);
}

static struct virshNetworkPortList *
virshNetworkPortListCollect(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags)
{
    struct virshNetworkPortList *list = g_new0(struct virshNetworkPortList, 1);
    int ret;
    g_autoptr(virshNetwork) network = NULL;
    bool success = false;

    if (!(network = virshCommandOptNetwork(ctl, cmd, NULL)))
        goto cleanup;

    if ((ret = virNetworkListAllPorts(network,
                                      &list->ports,
                                      flags)) < 0)
        goto cleanup;

    list->nports = ret;

    /* sort the list */
    if (list->ports && list->nports)
        qsort(list->ports, list->nports,
              sizeof(*list->ports), virshNetworkPortSorter);

    success = true;

 cleanup:
    if (!success) {
        g_clear_pointer(&list, virshNetworkPortListFree);
    }

    return list;
}

/*
 * "net-list" command
 */
static const vshCmdInfo info_network_port_list[] = {
    {.name = "help",
     .data = N_("list network ports")
    },
    {.name = "desc",
     .data = N_("Returns list of network ports.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_network_port_list[] = {
    VIRSH_COMMON_OPT_NETWORK_FULL(VIR_CONNECT_LIST_NETWORKS_ACTIVE),
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("list uuid's only")
    },
    {.name = "table",
     .type = VSH_OT_BOOL,
     .help = N_("list table (default)")
    },
    {.name = NULL}
};

static bool
cmdNetworkPortList(vshControl *ctl, const vshCmd *cmd)
{
    struct virshNetworkPortList *list = NULL;
    size_t i;
    bool ret = false;
    bool optTable = vshCommandOptBool(cmd, "table");
    bool optUUID = vshCommandOptBool(cmd, "uuid");
    char uuid[VIR_UUID_STRING_BUFLEN];
    unsigned int flags = 0;
    g_autoptr(vshTable) table = NULL;

    if (optTable + optUUID > 1) {
        vshError(ctl, "%s",
                 _("Only one argument from --table and --uuid may be specified."));
        return false;
    }

    if (!optUUID)
        optTable = true;

    if (!(list = virshNetworkPortListCollect(ctl, cmd, flags)))
        return false;

    if (optTable) {
        table = vshTableNew(_("UUID"), NULL);
        if (!table)
            goto cleanup;
    }

    for (i = 0; i < list->nports; i++) {
        virNetworkPortPtr port = list->ports[i];

        if (virNetworkPortGetUUIDString(port, uuid) < 0) {
            vshError(ctl, "%s", _("Failed to get network's UUID"));
            goto cleanup;
        }
        if (optTable) {
            if (vshTableRowAppend(table, uuid, NULL) < 0)
                goto cleanup;
        } else if (optUUID) {
            vshPrint(ctl, "%s\n", uuid);
        }
    }

    if (optTable)
        vshTablePrintToStdout(table, ctl);

    ret = true;
 cleanup:
    virshNetworkPortListFree(list);
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
    {.name = "net-desc",
     .handler = cmdNetworkDesc,
     .opts = opts_network_desc,
     .info = info_network_desc,
     .flags = 0
    },
    {.name = "net-destroy",
     .handler = cmdNetworkDestroy,
     .opts = opts_network_destroy,
     .info = info_network_destroy,
     .flags = 0
    },
    {.name = "net-dhcp-leases",
     .handler = cmdNetworkDHCPLeases,
     .opts = opts_network_dhcp_leases,
     .info = info_network_dhcp_leases,
     .flags = 0,
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
    {.name = "net-event",
     .handler = cmdNetworkEvent,
     .opts = opts_network_event,
     .info = info_network_event,
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
    {.name = "net-metadata",
     .handler = cmdNetworkMetadata,
     .opts = opts_network_metadata,
     .info = info_network_metadata,
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
    {.name = "net-port-list",
     .handler = cmdNetworkPortList,
     .opts = opts_network_port_list,
     .info = info_network_port_list,
     .flags = 0
    },
    {.name = "net-port-create",
     .handler = cmdNetworkPortCreate,
     .opts = opts_network_port_create,
     .info = info_network_port_create,
     .flags = 0
    },
    {.name = "net-port-dumpxml",
     .handler = cmdNetworkPortDumpXML,
     .opts = opts_network_port_dumpxml,
     .info = info_network_port_dumpxml,
     .flags = 0
    },
    {.name = "net-port-delete",
     .handler = cmdNetworkPortDelete,
     .opts = opts_network_port_delete,
     .info = info_network_port_delete,
     .flags = 0
    },
    {.name = NULL}
};
