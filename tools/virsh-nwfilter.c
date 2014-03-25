/*
 * virsh-nwfilter.c: Commands to manage network filters
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
#include "virsh-nwfilter.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virutil.h"
#include "virxml.h"

virNWFilterPtr
vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                        const char **name, unsigned int flags)
{
    virNWFilterPtr nwfilter = NULL;
    const char *n = NULL;
    const char *optname = "nwfilter";
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
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter UUID\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (!nwfilter && (flags & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter NAME\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByName(ctl->conn, n);
    }

    if (!nwfilter)
        vshError(ctl, _("failed to get nwfilter '%s'"), n);

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
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML network filter description")
    },
    {.name = NULL}
};

static bool
cmdNWFilterDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    nwfilter = virNWFilterDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (nwfilter != NULL) {
        vshPrint(ctl, _("Network filter %s defined from %s\n"),
                 virNWFilterGetName(nwfilter), from);
        virNWFilterFree(nwfilter);
    } else {
        vshError(ctl, _("Failed to define network filter from %s"), from);
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
     .help = N_("network filter name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNWFilterUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    const char *name;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, &name)))
        return false;

    if (virNWFilterUndefine(nwfilter) == 0) {
        vshPrint(ctl, _("Network filter %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network filter %s"), name);
        ret = false;
    }

    virNWFilterFree(nwfilter);
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
     .help = N_("network filter name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNWFilterDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    char *dump;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, NULL)))
        return false;

    dump = virNWFilterGetXMLDesc(nwfilter, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virNWFilterFree(nwfilter);
    return ret;
}

static int
vshNWFilterSorter(const void *a, const void *b)
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

struct vshNWFilterList {
    virNWFilterPtr *filters;
    size_t nfilters;
};
typedef struct vshNWFilterList *vshNWFilterListPtr;

static void
vshNWFilterListFree(vshNWFilterListPtr list)
{
    size_t i;

    if (list && list->filters) {
        for (i = 0; i < list->nfilters; i++) {
            if (list->filters[i])
                virNWFilterFree(list->filters[i]);
        }
        VIR_FREE(list->filters);
    }
    VIR_FREE(list);
}

static vshNWFilterListPtr
vshNWFilterListCollect(vshControl *ctl,
                       unsigned int flags)
{
    vshNWFilterListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    int ret;
    virNWFilterPtr filter;
    bool success = false;
    size_t deleted = 0;
    int nfilters = 0;
    char **names = NULL;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllNWFilters(ctl->conn,
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
    vshError(ctl, "%s", _("Failed to list node filters"));
    goto cleanup;


 fallback:
    /* fall back to old method (0.9.13 and older) */
    vshResetLibvirtError();

    nfilters = virConnectNumOfNWFilters(ctl->conn);
    if (nfilters < 0) {
        vshError(ctl, "%s", _("Failed to count network filters"));
        goto cleanup;
    }

    if (nfilters == 0)
        return list;

    names = vshMalloc(ctl, sizeof(char *) * nfilters);

    nfilters = virConnectListNWFilters(ctl->conn, names, nfilters);
    if (nfilters < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        goto cleanup;
    }

    list->filters = vshMalloc(ctl, sizeof(virNWFilterPtr) * nfilters);
    list->nfilters = 0;

    /* get the network filters */
    for (i = 0; i < nfilters; i++) {
        if (!(filter = virNWFilterLookupByName(ctl->conn, names[i])))
            continue;
        list->filters[list->nfilters++] = filter;
    }

    /* truncate network filters that weren't found */
    deleted = nfilters - list->nfilters;

 finished:
    /* sort the list */
    if (list->filters && list->nfilters)
        qsort(list->filters, list->nfilters,
              sizeof(*list->filters), vshNWFilterSorter);

    /* truncate the list for not found filter objects */
    if (deleted)
        VIR_SHRINK_N(list->filters, list->nfilters, deleted);

    success = true;

 cleanup:
    for (i = 0; nfilters != -1 && i < nfilters; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        vshNWFilterListFree(list);
        list = NULL;
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
cmdNWFilterList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    size_t i;
    char uuid[VIR_UUID_STRING_BUFLEN];
    vshNWFilterListPtr list = NULL;

    if (!(list = vshNWFilterListCollect(ctl, 0)))
        return false;

    vshPrintExtra(ctl, " %-36s  %-20s \n", _("UUID"), _("Name"));
    vshPrintExtra(ctl, "---------------------------------"
                       "---------------------------------\n");

    for (i = 0; i < list->nfilters; i++) {
        virNWFilterPtr nwfilter = list->filters[i];

        virNWFilterGetUUIDString(nwfilter, uuid);
        vshPrint(ctl, " %-36s  %-20s\n",
                 uuid,
                 virNWFilterGetName(nwfilter));
    }

    vshNWFilterListFree(list);
    return true;
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
     .help = N_("network filter name or uuid")
    },
    {.name = NULL}
};

static bool
cmdNWFilterEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNWFilterPtr nwfilter = NULL;
    virNWFilterPtr nwfilter_edited = NULL;

    nwfilter = vshCommandOptNWFilter(ctl, cmd, NULL);
    if (nwfilter == NULL)
        goto cleanup;

#define EDIT_GET_XML virNWFilterGetXMLDesc(nwfilter, 0)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Network filter %s XML "            \
                    "configuration not changed.\n"),    \
             virNWFilterGetName(nwfilter));             \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (nwfilter_edited = virNWFilterDefineXML(ctl->conn, doc_edited))
#define EDIT_FREE \
    if (nwfilter_edited)    \
        virNWFilterFree(nwfilter);
#include "virsh-edit.c"

    vshPrint(ctl, _("Network filter %s XML configuration edited.\n"),
             virNWFilterGetName(nwfilter_edited));

    ret = true;

 cleanup:
    if (nwfilter)
        virNWFilterFree(nwfilter);
    if (nwfilter_edited)
        virNWFilterFree(nwfilter_edited);

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
    {.name = NULL}
};
