/*
 * virsh-nwfilter.c: Commands to manage network filters
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
#include "virsh-nwfilter.h"
#include "virsh-util.h"

#include "internal.h"
#include "viralloc.h"
#include "virfile.h"
#include "vsh-table.h"

virNWFilterPtr
virshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                          const char **name, unsigned int flags)
{
    virNWFilterPtr nwfilter = NULL;
    const char *n = NULL;
    const char *optname = "nwfilter";
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
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter UUID\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByUUIDString(priv->conn, n);
    }
    /* try it by NAME */
    if (!nwfilter && (flags & VIRSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter NAME\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByName(priv->conn, n);
    }

    if (!nwfilter)
        vshError(ctl, _("failed to get nwfilter '%1$s'"), n);

    return nwfilter;
}

/*
 * "nwfilter-define" command
 */
static const vshCmdInfo info_nwfilter_define[] = {
    {.name = "help",
     .data = N_("define or update a network filter from an XML file")
    },
    {.name = "desc",
     .data = N_("Define a new network filter or update an existing one.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_define[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML network "
                             "filter description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdNWFilterDefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNWFilter) nwfilter = NULL;
    const char *from = NULL;
    bool ret = true;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_NWFILTER_DEFINE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (flags)
        nwfilter = virNWFilterDefineXMLFlags(priv->conn, buffer, flags);
    else
        nwfilter = virNWFilterDefineXML(priv->conn, buffer);

    if (nwfilter != NULL) {
        vshPrintExtra(ctl, _("Network filter %1$s defined from %2$s\n"),
                      virNWFilterGetName(nwfilter), from);
    } else {
        vshError(ctl, _("Failed to define network filter from %1$s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "nwfilter-undefine" command
 */
static const vshCmdInfo info_nwfilter_undefine[] = {
    {.name = "help",
     .data = N_("undefine a network filter")
    },
    {.name = "desc",
     .data = N_("Undefine a given network filter.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_undefine[] = {
    {.name = "nwfilter",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network filter name or uuid"),
     .completer = virshNWFilterNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdNWFilterUndefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNWFilter) nwfilter = NULL;
    bool ret = true;
    const char *name;

    if (!(nwfilter = virshCommandOptNWFilter(ctl, cmd, &name)))
        return false;

    if (virNWFilterUndefine(nwfilter) == 0) {
        vshPrintExtra(ctl, _("Network filter %1$s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network filter %1$s"), name);
        ret = false;
    }

    return ret;
}

/*
 * "nwfilter-dumpxml" command
 */
static const vshCmdInfo info_nwfilter_dumpxml[] = {
    {.name = "help",
     .data = N_("network filter information in XML")
    },
    {.name = "desc",
     .data = N_("Output the network filter information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_dumpxml[] = {
    {.name = "nwfilter",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network filter name or uuid"),
     .completer = virshNWFilterNameCompleter,
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
cmdNWFilterDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshNWFilter) nwfilter = NULL;
    g_autofree char *xml = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (!(nwfilter = virshCommandOptNWFilter(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virNWFilterGetXMLDesc(nwfilter, 0)))
        return false;

    return virshDumpXML(ctl, xml, "nwfilter", xpath, wrap);
}

static int
virshNWFilterSorter(const void *a, const void *b)
{
    virNWFilterPtr *fa = (virNWFilterPtr *) a;
    virNWFilterPtr *fb = (virNWFilterPtr *) b;

    if (*fa && !*fb)
        return -1;

    if (!*fa)
        return *fb != NULL;

    return vshStrcasecmp(virNWFilterGetName(*fa),
                         virNWFilterGetName(*fb));
}

struct virshNWFilterList {
    virNWFilterPtr *filters;
    size_t nfilters;
};

static void
virshNWFilterListFree(struct virshNWFilterList *list)
{
    size_t i;

    if (list && list->filters) {
        for (i = 0; i < list->nfilters; i++) {
            virshNWFilterFree(list->filters[i]);
        }
        g_free(list->filters);
    }
    g_free(list);
}

static struct virshNWFilterList *
virshNWFilterListCollect(vshControl *ctl,
                         unsigned int flags)
{
    struct virshNWFilterList *list = g_new0(struct virshNWFilterList, 1);
    size_t i;
    int ret;
    virNWFilterPtr filter;
    bool success = false;
    size_t deleted = 0;
    int nfilters = 0;
    char **names = NULL;
    virshControl *priv = ctl->privData;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllNWFilters(priv->conn,
                                          &list->filters,
                                          flags)) >= 0) {
        list->nfilters = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT) {
        vshResetLibvirtError();
        goto fallback;
    }

    /* there was an error during the call */
    vshError(ctl, "%s", _("Failed to list network filters"));
    goto cleanup;


 fallback:
    /* fall back to old method (0.9.13 and older) */
    vshResetLibvirtError();

    nfilters = virConnectNumOfNWFilters(priv->conn);
    if (nfilters < 0) {
        vshError(ctl, "%s", _("Failed to count network filters"));
        goto cleanup;
    }

    if (nfilters == 0)
        return list;

    names = g_new0(char *, nfilters);

    nfilters = virConnectListNWFilters(priv->conn, names, nfilters);
    if (nfilters < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        goto cleanup;
    }

    list->filters = g_new0(virNWFilterPtr, nfilters);
    list->nfilters = 0;

    /* get the network filters */
    for (i = 0; i < nfilters; i++) {
        if (!(filter = virNWFilterLookupByName(priv->conn, names[i])))
            continue;
        list->filters[list->nfilters++] = filter;
    }

    /* truncate network filters that weren't found */
    deleted = nfilters - list->nfilters;

 finished:
    /* sort the list */
    if (list->filters && list->nfilters)
        qsort(list->filters, list->nfilters,
              sizeof(*list->filters), virshNWFilterSorter);

    /* truncate the list for not found filter objects */
    if (deleted)
        VIR_SHRINK_N(list->filters, list->nfilters, deleted);

    success = true;

 cleanup:
    for (i = 0; nfilters != -1 && i < nfilters; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        g_clear_pointer(&list, virshNWFilterListFree);
    }

    return list;
}

/*
 * "nwfilter-list" command
 */
static const vshCmdInfo info_nwfilter_list[] = {
    {.name = "help",
     .data = N_("list network filters")
    },
    {.name = "desc",
     .data = N_("Returns list of network filters.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_list[] = {
    {.name = NULL}
};

static bool
cmdNWFilterList(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    size_t i;
    char uuid[VIR_UUID_STRING_BUFLEN];
    bool ret = false;
    struct virshNWFilterList *list = NULL;
    g_autoptr(vshTable) table = NULL;

    if (!(list = virshNWFilterListCollect(ctl, 0)))
        return false;

    table = vshTableNew(_("UUID"), _("Name"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < list->nfilters; i++) {
        virNWFilterPtr nwfilter = list->filters[i];

        virNWFilterGetUUIDString(nwfilter, uuid);
        if (vshTableRowAppend(table,
                              uuid,
                              virNWFilterGetName(nwfilter),
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;
 cleanup:
    virshNWFilterListFree(list);
    return ret;
}

/*
 * "nwfilter-edit" command
 */
static const vshCmdInfo info_nwfilter_edit[] = {
    {.name = "help",
     .data = N_("edit XML configuration for a network filter")
    },
    {.name = "desc",
     .data = N_("Edit the XML configuration for a network filter.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_edit[] = {
    {.name = "nwfilter",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network filter name or uuid"),
     .completer = virshNWFilterNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdNWFilterEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    g_autoptr(virshNWFilter) nwfilter = NULL;
    g_autoptr(virshNWFilter) nwfilter_edited = NULL;
    virshControl *priv = ctl->privData;

    nwfilter = virshCommandOptNWFilter(ctl, cmd, NULL);
    if (nwfilter == NULL)
        goto cleanup;

#define EDIT_GET_XML virNWFilterGetXMLDesc(nwfilter, 0)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Network filter %1$s XML configuration not changed.\n"), \
                      virNWFilterGetName(nwfilter)); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (nwfilter_edited = virNWFilterDefineXML(priv->conn, doc_edited))
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("Network filter %1$s XML configuration edited.\n"),
                  virNWFilterGetName(nwfilter_edited));

    ret = true;

 cleanup:
    return ret;
}


virNWFilterBindingPtr
virshCommandOptNWFilterBindingBy(vshControl *ctl,
                                 const vshCmd *cmd,
                                 const char **name,
                                 unsigned int flags)
{
    virNWFilterBindingPtr binding = NULL;
    const char *n = NULL;
    const char *optname = "binding";
    virshControl *priv = ctl->privData;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter binding port dev\n",
             cmd->def->name, optname);
    binding = virNWFilterBindingLookupByPortDev(priv->conn, n);

    if (!binding)
        vshError(ctl, _("failed to get nwfilter binding '%1$s'"), n);

    return binding;
}


/*
 * "nwfilter-binding-create" command
 */
static const vshCmdInfo info_nwfilter_binding_create[] = {
    {.name = "help",
     .data = N_("create a network filter binding from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a new network filter binding.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_binding_create[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML network "
                             "filter binding description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdNWFilterBindingCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterBindingPtr binding;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_NWFILTER_BINDING_CREATE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    binding = virNWFilterBindingCreateXML(priv->conn, buffer, flags);

    if (!binding) {
        vshError(ctl, _("Failed to create network filter from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Network filter binding on %1$s created from %2$s\n"),
                  virNWFilterBindingGetPortDev(binding), from);
    virNWFilterBindingFree(binding);
    return true;
}


/*
 * "nwfilter-binding-delete" command
 */
static const vshCmdInfo info_nwfilter_binding_delete[] = {
    {.name = "help",
     .data = N_("delete a network filter binding")
    },
    {.name = "desc",
     .data = N_("Delete a given network filter binding.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_binding_delete[] = {
    {.name = "binding",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network filter binding port dev"),
     .completer = virshNWFilterBindingNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdNWFilterBindingDelete(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterBindingPtr binding;
    bool ret = true;
    const char *portdev;

    if (!(binding = virshCommandOptNWFilterBinding(ctl, cmd, &portdev)))
        return false;

    if (virNWFilterBindingDelete(binding) == 0) {
        vshPrintExtra(ctl, _("Network filter binding on %1$s deleted\n"), portdev);
    } else {
        vshError(ctl, _("Failed to delete network filter binding on %1$s"), portdev);
        ret = false;
    }

    virNWFilterBindingFree(binding);
    return ret;
}


/*
 * "nwfilter-binding-dumpxml" command
 */
static const vshCmdInfo info_nwfilter_binding_dumpxml[] = {
    {.name = "help",
     .data = N_("network filter information in XML")
    },
    {.name = "desc",
     .data = N_("Output the network filter information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_binding_dumpxml[] = {
    {.name = "binding",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network filter binding portdev"),
     .completer = virshNWFilterBindingNameCompleter,
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
cmdNWFilterBindingDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterBindingPtr binding;
    bool ret = true;
    g_autofree char *xml = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (!(binding = virshCommandOptNWFilterBinding(ctl, cmd, NULL)))
        return false;

    if (!(xml = virNWFilterBindingGetXMLDesc(binding, 0)))
        goto cleanup;

    ret = virshDumpXML(ctl, xml, "nwfilter-binding", xpath, wrap);

 cleanup:
    virNWFilterBindingFree(binding);
    return ret;
}


static int
virshNWFilterBindingSorter(const void *a, const void *b)
{
    virNWFilterBindingPtr *fa = (virNWFilterBindingPtr *) a;
    virNWFilterBindingPtr *fb = (virNWFilterBindingPtr *) b;

    if (*fa && !*fb)
        return -1;

    if (!*fa)
        return *fb != NULL;

    return vshStrcasecmp(virNWFilterBindingGetPortDev(*fa),
                         virNWFilterBindingGetPortDev(*fb));
}


struct virshNWFilterBindingList {
    virNWFilterBindingPtr *bindings;
    size_t nbindings;
};


static void
virshNWFilterBindingListFree(struct virshNWFilterBindingList *list)
{
    size_t i;

    if (list && list->bindings) {
        for (i = 0; i < list->nbindings; i++) {
            if (list->bindings[i])
                virNWFilterBindingFree(list->bindings[i]);
        }
        g_free(list->bindings);
    }
    g_free(list);
}


static struct virshNWFilterBindingList *
virshNWFilterBindingListCollect(vshControl *ctl,
                                unsigned int flags)
{
    struct virshNWFilterBindingList *list = g_new0(struct virshNWFilterBindingList, 1);
    int ret;
    bool success = false;
    virshControl *priv = ctl->privData;

    if ((ret = virConnectListAllNWFilterBindings(priv->conn,
                                                 &list->bindings,
                                                 flags)) < 0) {
        /* there was an error during the call */
        vshError(ctl, "%s", _("Failed to list network filter bindings"));
        goto cleanup;
    }

    list->nbindings = ret;

    /* sort the list */
    if (list->bindings && list->nbindings > 1)
        qsort(list->bindings, list->nbindings,
              sizeof(*list->bindings), virshNWFilterBindingSorter);

    success = true;

 cleanup:
    if (!success) {
        g_clear_pointer(&list, virshNWFilterBindingListFree);
    }

    return list;
}


/*
 * "nwfilter-binding-list" command
 */
static const vshCmdInfo info_nwfilter_binding_list[] = {
    {.name = "help",
     .data = N_("list network filter bindings")
    },
    {.name = "desc",
     .data = N_("Returns list of network filter bindings.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_nwfilter_binding_list[] = {
    {.name = NULL}
};

static bool
cmdNWFilterBindingList(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    size_t i;
    bool ret = false;
    struct virshNWFilterBindingList *list = NULL;
    g_autoptr(vshTable) table = NULL;

    if (!(list = virshNWFilterBindingListCollect(ctl, 0)))
        return false;

    table = vshTableNew(_("Port Dev"), _("Filter"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < list->nbindings; i++) {
        virNWFilterBindingPtr binding = list->bindings[i];

        if (vshTableRowAppend(table,
                              virNWFilterBindingGetPortDev(binding),
                              virNWFilterBindingGetFilterName(binding),
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;
 cleanup:
    virshNWFilterBindingListFree(list);
    return ret;
}


const vshCmdDef nwfilterCmds[] = {
    {.name = "nwfilter-define",
     .handler = cmdNWFilterDefine,
     .opts = opts_nwfilter_define,
     .info = info_nwfilter_define,
     .flags = 0
    },
    {.name = "nwfilter-dumpxml",
     .handler = cmdNWFilterDumpXML,
     .opts = opts_nwfilter_dumpxml,
     .info = info_nwfilter_dumpxml,
     .flags = 0
    },
    {.name = "nwfilter-edit",
     .handler = cmdNWFilterEdit,
     .opts = opts_nwfilter_edit,
     .info = info_nwfilter_edit,
     .flags = 0
    },
    {.name = "nwfilter-list",
     .handler = cmdNWFilterList,
     .opts = opts_nwfilter_list,
     .info = info_nwfilter_list,
     .flags = 0
    },
    {.name = "nwfilter-undefine",
     .handler = cmdNWFilterUndefine,
     .opts = opts_nwfilter_undefine,
     .info = info_nwfilter_undefine,
     .flags = 0
    },
    {.name = "nwfilter-binding-create",
     .handler = cmdNWFilterBindingCreate,
     .opts = opts_nwfilter_binding_create,
     .info = info_nwfilter_binding_create,
     .flags = 0
    },
    {.name = "nwfilter-binding-delete",
     .handler = cmdNWFilterBindingDelete,
     .opts = opts_nwfilter_binding_delete,
     .info = info_nwfilter_binding_delete,
     .flags = 0
    },
    {.name = "nwfilter-binding-dumpxml",
     .handler = cmdNWFilterBindingDumpXML,
     .opts = opts_nwfilter_binding_dumpxml,
     .info = info_nwfilter_binding_dumpxml,
     .flags = 0
    },
    {.name = "nwfilter-binding-list",
     .handler = cmdNWFilterBindingList,
     .opts = opts_nwfilter_binding_list,
     .info = info_nwfilter_binding_list,
     .flags = 0
    },
    {.name = NULL}
};
