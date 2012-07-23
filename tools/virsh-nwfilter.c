/*
 * virsh-domain.c: Commands to manage network filters
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
#define vshCommandOptNWFilter(_ctl, _cmd, _name)                    \
    vshCommandOptNWFilterBy(_ctl, _cmd, _name,                      \
                            VSH_BYUUID|VSH_BYNAME)

static virNWFilterPtr
vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                        const char **name, int flag)
{
    virNWFilterPtr nwfilter = NULL;
    const char *n = NULL;
    const char *optname = "nwfilter";
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
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter UUID\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (nwfilter == NULL && (flag & VSH_BYNAME)) {
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
    {"help", N_("define or update a network filter from an XML file")},
    {"desc", N_("Define a new network filter or update an existing one.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network filter description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
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
    {"help", N_("undefine a network filter")},
    {"desc", N_("Undefine a given network filter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_undefine[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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
    {"help", N_("network filter information in XML")},
    {"desc", N_("Output the network filter information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_dumpxml[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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

/*
 * "nwfilter-list" command
 */
static const vshCmdInfo info_nwfilter_list[] = {
    {"help", N_("list network filters")},
    {"desc", N_("Returns list of network filters.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_list[] = {
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int numfilters, i;
    char **names;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    numfilters = virConnectNumOfNWFilters(ctl->conn);
    if (numfilters < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        return false;
    }

    names = vshMalloc(ctl, sizeof(char *) * numfilters);

    if ((numfilters = virConnectListNWFilters(ctl->conn, names,
                                              numfilters)) < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        VIR_FREE(names);
        return false;
    }

    qsort(&names[0], numfilters, sizeof(char *), vshNameSorter);

    vshPrintExtra(ctl, "%-36s  %-20s \n", _("UUID"), _("Name"));
    vshPrintExtra(ctl,
       "----------------------------------------------------------------\n");

    for (i = 0; i < numfilters; i++) {
        virNWFilterPtr nwfilter =
            virNWFilterLookupByName(ctl->conn, names[i]);

        /* this kind of work with networks is not atomic operation */
        if (!nwfilter) {
            VIR_FREE(names[i]);
            continue;
        }

        virNWFilterGetUUIDString(nwfilter, uuid);
        vshPrint(ctl, "%-36s  %-20s\n",
                 uuid,
                 virNWFilterGetName(nwfilter));
        virNWFilterFree(nwfilter);
        VIR_FREE(names[i]);
    }

    VIR_FREE(names);
    return true;
}

/*
 * "nwfilter-edit" command
 */
static const vshCmdInfo info_nwfilter_edit[] = {
    {"help", N_("edit XML configuration for a network filter")},
    {"desc", N_("Edit the XML configuration for a network filter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_edit[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNWFilterPtr nwfilter = NULL;
    virNWFilterPtr nwfilter_edited = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

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

static const vshCmdDef nwfilterCmds[] = {
    {"nwfilter-define", cmdNWFilterDefine, opts_nwfilter_define,
     info_nwfilter_define, 0},
    {"nwfilter-dumpxml", cmdNWFilterDumpXML, opts_nwfilter_dumpxml,
     info_nwfilter_dumpxml, 0},
    {"nwfilter-edit", cmdNWFilterEdit, opts_nwfilter_edit,
     info_nwfilter_edit, 0},
    {"nwfilter-list", cmdNWFilterList, opts_nwfilter_list,
     info_nwfilter_list, 0},
    {"nwfilter-undefine", cmdNWFilterUndefine, opts_nwfilter_undefine,
     info_nwfilter_undefine, 0},
    {NULL, NULL, NULL, NULL, 0}
};
