/*
 * virsh-interface.c: Commands to manage host interface
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
#include "virsh-interface.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virmacaddr.h"
#include "virutil.h"
#include "virxml.h"
#include "virstring.h"

virInterfacePtr
vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                         const char *optname,
                         const char **name, unsigned int flags)
{
    virInterfacePtr iface = NULL;
    const char *n = NULL;
    bool is_mac = false;
    virMacAddr dummy;
    virCheckFlags(VSH_BYNAME | VSH_BYMAC, NULL);

    if (!optname)
       optname = "interface";
    if (!vshCmdHasOption(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    if (virMacAddrParse(n, &dummy) == 0)
        is_mac = true;

    /* try it by NAME */
    if (!is_mac && (flags & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface NAME\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByName(ctl->conn, n);

    /* try it by MAC */
    } else if (is_mac && (flags & VSH_BYMAC)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface MAC\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByMACString(ctl->conn, n);
    }

    if (!iface)
        vshError(ctl, _("failed to get interface '%s'"), n);

    return iface;
}

/*
 * "iface-edit" command
 */
static const vshCmdInfo info_interface_edit[] = {
    {.name = "help",
     .data = N_("edit XML configuration for a physical host interface")
    },
    {.name = "desc",
     .data = N_("Edit the XML configuration for a physical host interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_edit[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name or MAC address")
    },
    {.name = NULL}
};

static bool
cmdInterfaceEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr iface = NULL;
    virInterfacePtr iface_edited = NULL;
    unsigned int flags = VIR_INTERFACE_XML_INACTIVE;

    iface = vshCommandOptInterface(ctl, cmd, NULL);
    if (iface == NULL)
        goto cleanup;

#define EDIT_GET_XML virInterfaceGetXMLDesc(iface, flags)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Interface %s XML configuration not changed.\n"),   \
             virInterfaceGetName(iface));                               \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (iface_edited = virInterfaceDefineXML(ctl->conn, doc_edited, 0))
#define EDIT_FREE \
    if (iface_edited)   \
        virInterfaceFree(iface_edited);
#include "virsh-edit.c"

    vshPrint(ctl, _("Interface %s XML configuration edited.\n"),
             virInterfaceGetName(iface_edited));

    ret = true;

 cleanup:
    if (iface)
        virInterfaceFree(iface);
    if (iface_edited)
        virInterfaceFree(iface_edited);

    return ret;
}

static int
vshInterfaceSorter(const void *a, const void *b)
{
    virInterfacePtr *ia = (virInterfacePtr *) a;
    virInterfacePtr *ib = (virInterfacePtr *) b;

    if (*ia && !*ib)
        return -1;

    if (!*ia)
        return *ib != NULL;

    return vshStrcasecmp(virInterfaceGetName(*ia),
                      virInterfaceGetName(*ib));
}

struct vshInterfaceList {
    virInterfacePtr *ifaces;
    size_t nifaces;
};
typedef struct vshInterfaceList *vshInterfaceListPtr;

static void
vshInterfaceListFree(vshInterfaceListPtr list)
{
    size_t i;

    if (list && list->ifaces) {
        for (i = 0; i < list->nifaces; i++) {
            if (list->ifaces[i])
                virInterfaceFree(list->ifaces[i]);
        }
        VIR_FREE(list->ifaces);
    }
    VIR_FREE(list);
}

static vshInterfaceListPtr
vshInterfaceListCollect(vshControl *ctl,
                        unsigned int flags)
{
    vshInterfaceListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    int ret;
    char **activeNames = NULL;
    char **inactiveNames = NULL;
    virInterfacePtr iface;
    bool success = false;
    size_t deleted = 0;
    int nActiveIfaces = 0;
    int nInactiveIfaces = 0;
    int nAllIfaces = 0;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllInterfaces(ctl->conn,
                                           &list->ifaces,
                                           flags)) >= 0) {
        list->nifaces = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    /* there was an error during the first or second call */
    vshError(ctl, "%s", _("Failed to list interfaces"));
    goto cleanup;


 fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    if (flags & VIR_CONNECT_LIST_INTERFACES_ACTIVE) {
        nActiveIfaces = virConnectNumOfInterfaces(ctl->conn);
        if (nActiveIfaces < 0) {
            vshError(ctl, "%s", _("Failed to list active interfaces"));
            goto cleanup;
        }
        if (nActiveIfaces) {
            activeNames = vshMalloc(ctl, sizeof(char *) * nActiveIfaces);

            if ((nActiveIfaces = virConnectListInterfaces(ctl->conn, activeNames,
                                                          nActiveIfaces)) < 0) {
                vshError(ctl, "%s", _("Failed to list active interfaces"));
                goto cleanup;
            }
        }
    }

    if (flags & VIR_CONNECT_LIST_INTERFACES_INACTIVE) {
        nInactiveIfaces = virConnectNumOfDefinedInterfaces(ctl->conn);
        if (nInactiveIfaces < 0) {
            vshError(ctl, "%s", _("Failed to list inactive interfaces"));
            goto cleanup;
        }
        if (nInactiveIfaces) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * nInactiveIfaces);

            if ((nInactiveIfaces =
                     virConnectListDefinedInterfaces(ctl->conn, inactiveNames,
                                                     nInactiveIfaces)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive interfaces"));
                goto cleanup;
            }
        }
    }

    nAllIfaces = nActiveIfaces + nInactiveIfaces;
    if (nAllIfaces == 0) {
        VIR_FREE(activeNames);
        VIR_FREE(inactiveNames);
        return list;
    }

    list->ifaces = vshMalloc(ctl, sizeof(virInterfacePtr) * (nAllIfaces));
    list->nifaces = 0;

    /* get active interfaces */
    for (i = 0; i < nActiveIfaces; i++) {
        if (!(iface = virInterfaceLookupByName(ctl->conn, activeNames[i]))) {
            vshResetLibvirtError();
            continue;
        }
        list->ifaces[list->nifaces++] = iface;
    }

    /* get inactive interfaces */
    for (i = 0; i < nInactiveIfaces; i++) {
        if (!(iface = virInterfaceLookupByName(ctl->conn, inactiveNames[i]))) {
            vshResetLibvirtError();
            continue;
        }
        list->ifaces[list->nifaces++] = iface;
    }

    /* truncate interfaces that weren't found */
    deleted = nAllIfaces - list->nifaces;

 finished:
    /* sort the list */
    if (list->ifaces && list->nifaces)
        qsort(list->ifaces, list->nifaces,
              sizeof(*list->ifaces), vshInterfaceSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->ifaces, list->nifaces, deleted);

    success = true;

 cleanup:
    for (i = 0; nActiveIfaces != -1 && i < nActiveIfaces; i++)
        VIR_FREE(activeNames[i]);

    for (i = 0; nInactiveIfaces != -1 && i < nInactiveIfaces; i++)
        VIR_FREE(inactiveNames[i]);

    VIR_FREE(activeNames);
    VIR_FREE(inactiveNames);

    if (!success) {
        vshInterfaceListFree(list);
        list = NULL;
    }

    return list;
}

/*
 * "iface-list" command
 */
static const vshCmdInfo info_interface_list[] = {
    {.name = "help",
     .data = N_("list physical host interfaces")
    },
    {.name = "desc",
     .data = N_("Returns list of physical host interfaces.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_list[] = {
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive interfaces")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive & active interfaces")
    },
    {.name = NULL}
};

static bool
cmdInterfaceList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool all = vshCommandOptBool(cmd, "all");
    unsigned int flags = VIR_CONNECT_LIST_INTERFACES_ACTIVE;
    vshInterfaceListPtr list = NULL;
    size_t i;

    if (inactive)
        flags = VIR_CONNECT_LIST_INTERFACES_INACTIVE;
    if (all)
        flags = VIR_CONNECT_LIST_INTERFACES_INACTIVE |
                VIR_CONNECT_LIST_INTERFACES_ACTIVE;

    if (!(list = vshInterfaceListCollect(ctl, flags)))
        return false;

    vshPrintExtra(ctl, " %-20s %-10s %s\n", _("Name"), _("State"),
                  _("MAC Address"));
    vshPrintExtra(ctl, "---------------------------------------------------\n");

    for (i = 0; i < list->nifaces; i++) {
        virInterfacePtr iface = list->ifaces[i];

        vshPrint(ctl, " %-20s %-10s %s\n",
                 virInterfaceGetName(iface),
                 virInterfaceIsActive(iface) ? _("active") : _("inactive"),
                 virInterfaceGetMACString(iface));
    }

    vshInterfaceListFree(list);
    return true;
}

/*
 * "iface-name" command
 */
static const vshCmdInfo info_interface_name[] = {
    {.name = "help",
     .data = N_("convert an interface MAC address to interface name")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_name[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface mac")
    },
    {.name = NULL}
};

static bool
cmdInterfaceName(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL, NULL,
                                           VSH_BYMAC)))
        return false;

    vshPrint(ctl, "%s\n", virInterfaceGetName(iface));
    virInterfaceFree(iface);
    return true;
}

/*
 * "iface-mac" command
 */
static const vshCmdInfo info_interface_mac[] = {
    {.name = "help",
     .data = N_("convert an interface name to interface MAC address")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_mac[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name")
    },
    {.name = NULL}
};

static bool
cmdInterfaceMAC(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL, NULL,
                                           VSH_BYNAME)))
        return false;

    vshPrint(ctl, "%s\n", virInterfaceGetMACString(iface));
    virInterfaceFree(iface);
    return true;
}

/*
 * "iface-dumpxml" command
 */
static const vshCmdInfo info_interface_dumpxml[] = {
    {.name = "help",
     .data = N_("interface information in XML")
    },
    {.name = "desc",
     .data = N_("Output the physical host interface information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_dumpxml[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name or MAC address")
    },
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("show inactive defined XML")
    },
    {.name = NULL}
};

static bool
cmdInterfaceDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    bool inactive = vshCommandOptBool(cmd, "inactive");

    if (inactive)
        flags |= VIR_INTERFACE_XML_INACTIVE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, NULL)))
        return false;

    dump = virInterfaceGetXMLDesc(iface, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-define" command
 */
static const vshCmdInfo info_interface_define[] = {
    {.name = "help",
     .data = N_("define (but don't start) a physical host interface from an XML file")
    },
    {.name = "desc",
     .data = N_("Define a physical host interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_define[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML interface description")
    },
    {.name = NULL}
};

static bool
cmdInterfaceDefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    iface = virInterfaceDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (iface != NULL) {
        vshPrint(ctl, _("Interface %s defined from %s\n"),
                 virInterfaceGetName(iface), from);
        virInterfaceFree(iface);
    } else {
        vshError(ctl, _("Failed to define interface from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "iface-undefine" command
 */
static const vshCmdInfo info_interface_undefine[] = {
    {.name = "help",
     .data = N_("undefine a physical host interface (remove it from configuration)")
    },
    {.name = "desc",
     .data = N_("undefine an interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_undefine[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name or MAC address")
    },
    {.name = NULL}
};

static bool
cmdInterfaceUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceUndefine(iface) == 0) {
        vshPrint(ctl, _("Interface %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-start" command
 */
static const vshCmdInfo info_interface_start[] = {
    {.name = "help",
     .data = N_("start a physical host interface (enable it / \"if-up\")")
    },
    {.name = "desc",
     .data = N_("start a physical host interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_start[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name or MAC address")
    },
    {.name = NULL}
};

static bool
cmdInterfaceStart(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceCreate(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-destroy" command
 */
static const vshCmdInfo info_interface_destroy[] = {
    {.name = "help",
     .data = N_("destroy a physical host interface (disable it / \"if-down\")")
    },
    {.name = "desc",
     .data = N_("forcefully stop a physical host interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_destroy[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface name or MAC address")
    },
    {.name = NULL}
};

static bool
cmdInterfaceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceDestroy(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-begin" command
 */
static const vshCmdInfo info_interface_begin[] = {
    {.name = "help",
     .data = N_("create a snapshot of current interfaces settings, "
                "which can be later committed (iface-commit) or "
                "restored (iface-rollback)")
    },
    {.name = "desc",
     .data = N_("Create a restore point for interfaces settings")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_begin[] = {
    {.name = NULL}
};

static bool
cmdInterfaceBegin(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (virInterfaceChangeBegin(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to begin network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction started\n"));
    return true;
}

/*
 * "iface-commit" command
 */
static const vshCmdInfo info_interface_commit[] = {
    {.name = "help",
     .data = N_("commit changes made since iface-begin and free restore point")
    },
    {.name = "desc",
     .data = N_("commit changes and free restore point")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_commit[] = {
    {.name = NULL}
};

static bool
cmdInterfaceCommit(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (virInterfaceChangeCommit(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to commit network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction committed\n"));
    return true;
}

/*
 * "iface-rollback" command
 */
static const vshCmdInfo info_interface_rollback[] = {
    {.name = "help",
     .data = N_("rollback to previous saved configuration created via iface-begin")
    },
    {.name = "desc",
     .data = N_("rollback to previous restore point")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_rollback[] = {
    {.name = NULL}
};

static bool
cmdInterfaceRollback(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (virInterfaceChangeRollback(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to rollback network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction rolled back\n"));
    return true;
}

/*
 * "iface-bridge" command
 */
static const vshCmdInfo info_interface_bridge[] = {
    {.name = "help",
     .data = N_("create a bridge device and attach an existing network device to it")
    },
    {.name = "desc",
     .data = N_("bridge an existing network device")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_bridge[] = {
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("existing interface name")
    },
    {.name = "bridge",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new bridge device name")
    },
    {.name = "no-stp",
     .type = VSH_OT_BOOL,
     .help = N_("do not enable STP for this bridge")
    },
    {.name = "delay",
     .type = VSH_OT_INT,
     .help = N_("number of seconds to squelch traffic on newly connected ports")
    },
    {.name = "no-start",
     .type = VSH_OT_BOOL,
     .help = N_("don't start the bridge immediately")
    },
    {.name = NULL}
};

static bool
cmdInterfaceBridge(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr if_handle = NULL, br_handle = NULL;
    const char *if_name, *br_name;
    char *if_type = NULL, *if2_name = NULL, *delay_str = NULL;
    bool stp = false, nostart = false;
    unsigned int delay = 0;
    char *if_xml = NULL;
    xmlChar *br_xml = NULL;
    int br_xml_size;
    xmlDocPtr xml_doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr top_node, br_node, if_node, cur;

    /* Get a handle to the original device */
    if (!(if_handle = vshCommandOptInterfaceBy(ctl, cmd, "interface",
                                               &if_name, VSH_BYNAME))) {
        goto cleanup;
    }

    /* Name for new bridge device */
    if (vshCommandOptStringReq(ctl, cmd, "bridge", &br_name) < 0)
        goto cleanup;

    /* make sure "new" device doesn't already exist */
    if ((br_handle = virInterfaceLookupByName(ctl->conn, br_name))) {
        vshError(ctl, _("Network device %s already exists"), br_name);
        goto cleanup;
    }

    /* use "no-stp" because we want "stp" to default true */
    stp = !vshCommandOptBool(cmd, "no-stp");

    if (vshCommandOptUInt(cmd, "delay", &delay) < 0) {
        vshError(ctl, "%s", _("Unable to parse delay parameter"));
        goto cleanup;
    }

    nostart = vshCommandOptBool(cmd, "no-start");

    /* Get the original interface into an xmlDoc */
    if (!(if_xml = virInterfaceGetXMLDesc(if_handle, VIR_INTERFACE_XML_INACTIVE)))
        goto cleanup;
    if (!(xml_doc = virXMLParseStringCtxt(if_xml,
                                          _("(interface definition)"), &ctxt))) {
        vshError(ctl, _("Failed to parse configuration of %s"), if_name);
        goto cleanup;
    }
    top_node = ctxt->node;

    /* Verify that the original device isn't already a bridge. */
    if (!(if_type = virXMLPropString(top_node, "type"))) {
        vshError(ctl, _("Existing device %s has no type"), if_name);
        goto cleanup;
    }

    if (STREQ(if_type, "bridge")) {
        vshError(ctl, _("Existing device %s is already a bridge"), if_name);
        goto cleanup;
    }

    /* verify the name in the XML matches the device name */
    if (!(if2_name = virXMLPropString(top_node, "name")) ||
        STRNEQ(if2_name, if_name)) {
        vshError(ctl, _("Interface name from config %s doesn't match given supplied name %s"),
                 if2_name, if_name);
        goto cleanup;
    }

    /* Create a <bridge> node under <interface>. */
    if (!(br_node = xmlNewChild(top_node, NULL, BAD_CAST "bridge", NULL))) {
        vshError(ctl, "%s", _("Failed to create bridge node in xml document"));
        goto cleanup;
    }

    /* Set stp and delay attributes in <bridge> according to the
     * commandline options.
     */
    if (!xmlSetProp(br_node, BAD_CAST "stp", BAD_CAST(stp ? "on" : "off"))) {
        vshError(ctl, "%s", _("Failed to set stp attribute in xml document"));
        goto cleanup;
    }

    if (stp &&
        ((virAsprintf(&delay_str, "%d", delay) < 0) ||
         !xmlSetProp(br_node, BAD_CAST "delay", BAD_CAST delay_str))) {
        vshError(ctl, _("Failed to set bridge delay %d in xml document"), delay);
        goto cleanup;
    }

    /* Change the type of the outer/master interface to "bridge" and the
     * name to the provided bridge name.
     */
    if (!xmlSetProp(top_node, BAD_CAST "type", BAD_CAST "bridge")) {
        vshError(ctl, "%s", _("Failed to set bridge interface type to 'bridge' in xml document"));
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "name", BAD_CAST br_name)) {
        vshError(ctl, _("Failed to set master bridge interface name to '%s' in xml document"),
            br_name);
        goto cleanup;
    }

    /* Create an <interface> node under <bridge> that uses the
     * original interface's type and name.
     */
    if (!(if_node = xmlNewChild(br_node, NULL, BAD_CAST "interface", NULL))) {
        vshError(ctl, "%s", _("Failed to create interface node under bridge node in xml document"));
        goto cleanup;
    }

    /* set the type of the inner/slave interface to the original
     * if_type, and the name to the original if_name.
     */
    if (!xmlSetProp(if_node, BAD_CAST "type", BAD_CAST if_type)) {
        vshError(ctl, _("Failed to set new slave interface type to '%s' in xml document"),
                 if_type);
        goto cleanup;
    }

    if (!xmlSetProp(if_node, BAD_CAST "name", BAD_CAST if_name)) {
        vshError(ctl, _("Failed to set new slave interface name to '%s' in xml document"),
                 if_name);
        goto cleanup;
    }

    /* Cycle through all the nodes under the original <interface>,
     * moving all <mac>, <bond> and <vlan> nodes down into the new
     * lower level <interface>.
     */
    cur = top_node->children;
    while (cur) {
        xmlNodePtr old = cur;

        cur = cur->next;
        if ((old->type == XML_ELEMENT_NODE) &&
            (xmlStrEqual(old->name, BAD_CAST "mac") ||  /* ethernet stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "bond") || /* bond stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "vlan"))) { /* vlan stuff to move down */
            xmlUnlinkNode(old);
            if (!xmlAddChild(if_node, old)) {
                vshError(ctl, _("Failed to move '%s' element in xml document"), old->name);
                xmlFreeNode(old);
                goto cleanup;
            }
        }
    }

    /* The document should now be fully converted; write it out to a string. */
    xmlDocDumpMemory(xml_doc, &br_xml, &br_xml_size);

    if (!br_xml || br_xml_size <= 0) {
        vshError(ctl, _("Failed to format new xml document for bridge %s"), br_name);
        goto cleanup;
    }


    /* br_xml is the new interface to define. It will automatically undefine the
     * independent original interface.
     */
    if (!(br_handle = virInterfaceDefineXML(ctl->conn, (char *) br_xml, 0))) {
        vshError(ctl, _("Failed to define new bridge interface %s"),
                 br_name);
        goto cleanup;
    }

    vshPrint(ctl, _("Created bridge %s with attached device %s\n"),
             br_name, if_name);

    /* start it up unless requested not to */
    if (!nostart) {
        if (virInterfaceCreate(br_handle, 0) < 0) {
            vshError(ctl, _("Failed to start bridge interface %s"), br_name);
            goto cleanup;
        }
        vshPrint(ctl, _("Bridge interface %s started\n"), br_name);
    }

    ret = true;
 cleanup:
    if (if_handle)
       virInterfaceFree(if_handle);
    if (br_handle)
       virInterfaceFree(br_handle);
    VIR_FREE(if_xml);
    VIR_FREE(br_xml);
    VIR_FREE(if_type);
    VIR_FREE(if2_name);
    VIR_FREE(delay_str);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml_doc);
    return ret;
}

/*
 * "iface-unbridge" command
 */
static const vshCmdInfo info_interface_unbridge[] = {
    {.name = "help",
     .data = N_("undefine a bridge device after detaching its slave device")
    },
    {.name = "desc",
     .data = N_("unbridge a network device")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_interface_unbridge[] = {
    {.name = "bridge",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("current bridge device name")
    },
    {.name = "no-start",
     .type = VSH_OT_BOOL,
     .help = N_("don't start the un-slaved interface immediately (not recommended)")
    },
    {.name = NULL}
};

static bool
cmdInterfaceUnbridge(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr if_handle = NULL, br_handle = NULL;
    const char *br_name;
    char *if_type = NULL, *if_name = NULL;
    bool nostart = false;
    char *br_xml = NULL;
    xmlChar *if_xml = NULL;
    int if_xml_size;
    xmlDocPtr xml_doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr top_node, if_node, cur;

    /* Get a handle to the original device */
    if (!(br_handle = vshCommandOptInterfaceBy(ctl, cmd, "bridge",
                                               &br_name, VSH_BYNAME))) {
        goto cleanup;
    }

    nostart = vshCommandOptBool(cmd, "no-start");

    /* Get the bridge xml into an xmlDoc */
    if (!(br_xml = virInterfaceGetXMLDesc(br_handle, VIR_INTERFACE_XML_INACTIVE)))
        goto cleanup;
    if (!(xml_doc = virXMLParseStringCtxt(br_xml,
                                          _("(bridge interface definition)"),
                                          &ctxt))) {
        vshError(ctl, _("Failed to parse configuration of %s"), br_name);
        goto cleanup;
    }
    top_node = ctxt->node;

    /* Verify that the device really is a bridge. */
    if (!(if_type = virXMLPropString(top_node, "type"))) {
        vshError(ctl, _("Existing device %s has no type"), br_name);
        goto cleanup;
    }

    if (STRNEQ(if_type, "bridge")) {
        vshError(ctl, _("Device %s is not a bridge"), br_name);
        goto cleanup;
    }
    VIR_FREE(if_type);

    /* verify the name in the XML matches the device name */
    if (!(if_name = virXMLPropString(top_node, "name")) ||
        STRNEQ(if_name, br_name)) {
        vshError(ctl, _("Interface name from config %s doesn't match given supplied name %s"),
                 if_name, br_name);
        goto cleanup;
    }
    VIR_FREE(if_name);

    /* Find the <bridge> node under <interface>. */
    if (virXPathNode("./bridge", ctxt) == NULL) {
        vshError(ctl, "%s", _("No bridge node in xml document"));
        goto cleanup;
    }

    if (virXPathNode("./bridge/interface[2]", ctxt) != NULL) {
        vshError(ctl, "%s", _("Multiple interfaces attached to bridge"));
        goto cleanup;
    }

    if (!(if_node = virXPathNode("./bridge/interface", ctxt))) {
        vshError(ctl, "%s", _("No interface attached to bridge"));
        goto cleanup;
    }

    /* Change the type and name of the outer/master interface to
     * the type/name of the attached slave interface.
     */
    if (!(if_name = virXMLPropString(if_node, "name"))) {
        vshError(ctl, _("Device attached to bridge %s has no name"), br_name);
        goto cleanup;
    }

    if (!(if_type = virXMLPropString(if_node, "type"))) {
        vshError(ctl, _("Attached device %s has no type"), if_name);
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "type", BAD_CAST if_type)) {
        vshError(ctl, _("Failed to set interface type to '%s' in xml document"),
                 if_type);
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "name", BAD_CAST if_name)) {
        vshError(ctl, _("Failed to set interface name to '%s' in xml document"),
                 if_name);
        goto cleanup;
    }

    /* Cycle through all the nodes under the attached <interface>,
     * moving all <mac>, <bond> and <vlan> nodes up into the toplevel
     * <interface>.
     */
    cur = if_node->children;
    while (cur) {
        xmlNodePtr old = cur;

        cur = cur->next;
        if ((old->type == XML_ELEMENT_NODE) &&
            (xmlStrEqual(old->name, BAD_CAST "mac") ||  /* ethernet stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "bond") || /* bond stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "vlan"))) { /* vlan stuff to move down */
            xmlUnlinkNode(old);
            if (!xmlAddChild(top_node, old)) {
                vshError(ctl, _("Failed to move '%s' element in xml document"), old->name);
                xmlFreeNode(old);
                goto cleanup;
            }
        }
    }

    /* The document should now be fully converted; write it out to a string. */
    xmlDocDumpMemory(xml_doc, &if_xml, &if_xml_size);

    if (!if_xml || if_xml_size <= 0) {
        vshError(ctl, _("Failed to format new xml document for un-enslaved interface %s"),
                 if_name);
        goto cleanup;
    }

    /* Destroy and Undefine the bridge device, since we otherwise
     * can't safely define the unattached device.
     */
    if (virInterfaceDestroy(br_handle, 0) < 0) {
        vshError(ctl, _("Failed to destroy bridge interface %s"), br_name);
        goto cleanup;
    }
    if (virInterfaceUndefine(br_handle) < 0) {
        vshError(ctl, _("Failed to undefine bridge interface %s"), br_name);
        goto cleanup;
    }

    /* if_xml is the new interface to define.
     */
    if (!(if_handle = virInterfaceDefineXML(ctl->conn, (char *) if_xml, 0))) {
        vshError(ctl, _("Failed to define new interface %s"), if_name);
        goto cleanup;
    }

    vshPrint(ctl, _("Device %s un-attached from bridge %s\n"),
             if_name, br_name);

    /* unless requested otherwise, undefine the bridge device */
    if (!nostart) {
        if (virInterfaceCreate(if_handle, 0) < 0) {
            vshError(ctl, _("Failed to start interface %s"), if_name);
            goto cleanup;
        }
        vshPrint(ctl, _("Interface %s started\n"), if_name);
    }

    ret = true;
 cleanup:
    if (if_handle)
       virInterfaceFree(if_handle);
    if (br_handle)
       virInterfaceFree(br_handle);
    VIR_FREE(if_xml);
    VIR_FREE(br_xml);
    VIR_FREE(if_type);
    VIR_FREE(if_name);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml_doc);
    return ret;
}

const vshCmdDef ifaceCmds[] = {
    {.name = "iface-begin",
     .handler = cmdInterfaceBegin,
     .opts = opts_interface_begin,
     .info = info_interface_begin,
     .flags = 0
    },
    {.name = "iface-bridge",
     .handler = cmdInterfaceBridge,
     .opts = opts_interface_bridge,
     .info = info_interface_bridge,
     .flags = 0
    },
    {.name = "iface-commit",
     .handler = cmdInterfaceCommit,
     .opts = opts_interface_commit,
     .info = info_interface_commit,
     .flags = 0
    },
    {.name = "iface-define",
     .handler = cmdInterfaceDefine,
     .opts = opts_interface_define,
     .info = info_interface_define,
     .flags = 0
    },
    {.name = "iface-destroy",
     .handler = cmdInterfaceDestroy,
     .opts = opts_interface_destroy,
     .info = info_interface_destroy,
     .flags = 0
    },
    {.name = "iface-dumpxml",
     .handler = cmdInterfaceDumpXML,
     .opts = opts_interface_dumpxml,
     .info = info_interface_dumpxml,
     .flags = 0
    },
    {.name = "iface-edit",
     .handler = cmdInterfaceEdit,
     .opts = opts_interface_edit,
     .info = info_interface_edit,
     .flags = 0
    },
    {.name = "iface-list",
     .handler = cmdInterfaceList,
     .opts = opts_interface_list,
     .info = info_interface_list,
     .flags = 0
    },
    {.name = "iface-mac",
     .handler = cmdInterfaceMAC,
     .opts = opts_interface_mac,
     .info = info_interface_mac,
     .flags = 0
    },
    {.name = "iface-name",
     .handler = cmdInterfaceName,
     .opts = opts_interface_name,
     .info = info_interface_name,
     .flags = 0
    },
    {.name = "iface-rollback",
     .handler = cmdInterfaceRollback,
     .opts = opts_interface_rollback,
     .info = info_interface_rollback,
     .flags = 0
    },
    {.name = "iface-start",
     .handler = cmdInterfaceStart,
     .opts = opts_interface_start,
     .info = info_interface_start,
     .flags = 0
    },
    {.name = "iface-unbridge",
     .handler = cmdInterfaceUnbridge,
     .opts = opts_interface_unbridge,
     .info = info_interface_unbridge,
     .flags = 0
    },
    {.name = "iface-undefine",
     .handler = cmdInterfaceUndefine,
     .opts = opts_interface_undefine,
     .info = info_interface_undefine,
     .flags = 0
    },
    {.name = NULL}
};
