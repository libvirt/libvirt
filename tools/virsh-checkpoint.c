/*
 * virsh-checkpoint.c: Commands to manage domain checkpoints
 *
 * Copyright (C) 2005-2019 Red Hat, Inc.
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
#include "virsh-checkpoint.h"

#include <assert.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virsh-util.h"
#include "virxml.h"
#include "vsh-table.h"

/* Helper for checkpoint-create and checkpoint-create-as */
static bool
virshCheckpointCreate(vshControl *ctl,
                      virDomainPtr dom,
                      const char *buffer,
                      unsigned int flags,
                      const char *from)
{
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    const char *name = NULL;

    checkpoint = virDomainCheckpointCreateXML(dom, buffer, flags);

    if (checkpoint == NULL)
        return false;

    name = virDomainCheckpointGetName(checkpoint);
    if (!name) {
        vshError(ctl, "%s", _("Could not get checkpoint name"));
        return false;
    }

    if (from)
        vshPrintExtra(ctl, _("Domain checkpoint %1$s created from '%2$s'"),
                      name, from);
    else
        vshPrintExtra(ctl, _("Domain checkpoint %1$s created"), name);

    return true;
}


/*
 * "checkpoint-create" command
 */
static const vshCmdInfo info_checkpoint_create[] = {
    {.name = "help",
     .data = N_("Create a checkpoint from XML")
    },
    {.name = "desc",
     .data = N_("Create a checkpoint from XML for use in "
                "future incremental backups")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_create[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "xmlfile",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("domain checkpoint XML")
    },
    {.name = "redefine",
     .type = VSH_OT_BOOL,
     .help = N_("redefine metadata for existing checkpoint")
    },
    {.name = "redefine-validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the redefined checkpoint")
    },
    {.name = "quiesce",
     .type = VSH_OT_BOOL,
     .help = N_("quiesce guest's file systems")
    },
    {.name = NULL}
};

static bool
cmdCheckpointCreate(vshControl *ctl,
                    const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;

    VSH_REQUIRE_OPTION("redefine-validate", "redefine");

    if (vshCommandOptBool(cmd, "redefine"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE;
    if (vshCommandOptBool(cmd, "redefine-validate"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE_VALIDATE;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "xmlfile", &from) < 0)
        return false;
    if (!from) {
        buffer = g_strdup("<domaincheckpoint/>");
    } else {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            vshSaveLibvirtError();
            return false;
        }
    }

    return virshCheckpointCreate(ctl, dom, buffer, flags, from);
}


/*
 * "checkpoint-create-as" command
 */
static int
virshParseCheckpointDiskspec(vshControl *ctl,
                             virBuffer *buf,
                             const char *str)
{
    int ret = -1;
    const char *name = NULL;
    const char *checkpoint = NULL;
    const char *bitmap = NULL;
    g_auto(GStrv) array = NULL;
    int narray;
    size_t i;

    narray = vshStringToArray(str, &array);
    if (narray <= 0)
        goto cleanup;

    name = array[0];
    for (i = 1; i < narray; i++) {
        if (!checkpoint && STRPREFIX(array[i], "checkpoint="))
            checkpoint = array[i] + strlen("checkpoint=");
        else if (!bitmap && STRPREFIX(array[i], "bitmap="))
            bitmap = array[i] + strlen("bitmap=");
        else
            goto cleanup;
    }

    virBufferEscapeString(buf, "<disk name='%s'", name);
    if (checkpoint)
        virBufferAsprintf(buf, " checkpoint='%s'", checkpoint);
    if (bitmap)
        virBufferAsprintf(buf, " bitmap='%s'", bitmap);
    virBufferAddLit(buf, "/>\n");
    ret = 0;
 cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse diskspec: %1$s"), str);
    return ret;
}

static const vshCmdInfo info_checkpoint_create_as[] = {
    {.name = "help",
     .data = N_("Create a checkpoint from a set of args")
    },
    {.name = "desc",
     .data = N_("Create a checkpoint from arguments for use in "
                "future incremental backups")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_create_as[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "name",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("name of checkpoint")
    },
    {.name = "description",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("description of checkpoint")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than create")
    },
    {.name = "quiesce",
     .type = VSH_OT_BOOL,
     .help = N_("quiesce guest's file systems")
    },
    {.name = "diskspec",
     .type = VSH_OT_ARGV,
     .help = N_("disk attributes: disk[,checkpoint=type][,bitmap=name]")
    },
    {.name = NULL}
};


static bool
cmdCheckpointCreateAs(vshControl *ctl,
                      const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;

    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "description", &desc) < 0)
        return false;

    virBufferAddLit(&buf, "<domaincheckpoint>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", name);
    virBufferEscapeString(&buf, "<description>%s</description>\n", desc);

    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "<disks>\n");
        virBufferAdjustIndent(&buf, 2);
        while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
            if (virshParseCheckpointDiskspec(ctl, &buf, opt->data) < 0)
                return false;
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</disks>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domaincheckpoint>\n");

    buffer = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s\n",  buffer);
        return true;
    }

    return virshCheckpointCreate(ctl, dom, buffer, flags, NULL);
}


/* Helper for resolving --ARG name into a checkpoint
 * belonging to DOM.  On success, populate *CHK and *NAME, before
 * returning 0.  On failure, return -1 after issuing an error
 * message.  */
static int
virshLookupCheckpoint(vshControl *ctl,
                      const vshCmd *cmd,
                      const char *arg,
                      virDomainPtr dom,
                      virDomainCheckpointPtr *chk,
                      const char **name)
{
    const char *chkname = NULL;

    if (vshCommandOptStringReq(ctl, cmd, arg, &chkname) < 0)
        return -1;

    if (chkname) {
        *chk = virDomainCheckpointLookupByName(dom, chkname, 0);
    } else {
        vshError(ctl, _("--%1$s is required"), arg);
        return -1;
    }
    if (!*chk) {
        vshReportError(ctl);
        return -1;
    }

    *name = virDomainCheckpointGetName(*chk);
    return 0;
}


/*
 * "checkpoint-edit" command
 */
static const vshCmdInfo info_checkpoint_edit[] = {
    {.name = "help",
     .data = N_("edit XML for a checkpoint")
    },
    {.name = "desc",
     .data = N_("Edit the domain checkpoint XML for a named checkpoint")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_edit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT),
    {.name = "checkpointname",
     .type = VSH_OT_STRING,
     .help = N_("checkpoint name"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdCheckpointEdit(vshControl *ctl,
                  const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    g_autoptr(virshDomainCheckpoint) edited = NULL;
    const char *name = NULL;
    const char *edited_name;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_CHECKPOINT_XML_SECURE;
    unsigned int define_flags = VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        goto cleanup;

#define EDIT_GET_XML \
    virDomainCheckpointGetXMLDesc(checkpoint, getxml_flags)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, \
                      _("Checkpoint %1$s XML configuration not changed.\n"), \
                      name); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    edited = virDomainCheckpointCreateXML(dom, doc_edited, define_flags)
#include "virsh-edit.c"

    edited_name = virDomainCheckpointGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrintExtra(ctl, _("Checkpoint %1$s edited.\n"), name);
    } else {
        unsigned int delete_flags = VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY;

        if (virDomainCheckpointDelete(edited, delete_flags) < 0) {
            vshReportError(ctl);
            vshError(ctl, _("Failed to clean up %1$s"), edited_name);
            goto cleanup;
        }
        vshError(ctl, _("Cannot rename checkpoint %1$s to %2$s"),
                 name, edited_name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    if (!ret && name)
        vshError(ctl, _("Failed to update %1$s"), name);
    return ret;
}


/* Helper function to get the name of a checkpoint's parent.  Caller
 * must free the result.  Returns 0 on success (including when it was
 * proven no parent exists), and -1 on failure with error reported
 * (such as no checkpoint support or domain deleted in meantime).  */
static int
virshGetCheckpointParent(vshControl *ctl,
                         virDomainCheckpointPtr checkpoint,
                         char **parent_name)
{
    g_autoptr(virshDomainCheckpoint) parent = NULL;
    int ret = -1;

    *parent_name = NULL;

    parent = virDomainCheckpointGetParent(checkpoint, 0);
    if (parent) {
        /* API works, and virDomainCheckpointGetName will succeed */
        *parent_name = g_strdup(virDomainCheckpointGetName(parent));
        ret = 0;
    } else if (last_error->code == VIR_ERR_NO_DOMAIN_CHECKPOINT) {
        /* API works, and we found a root with no parent */
        ret = 0;
    }

    if (ret < 0) {
        vshReportError(ctl);
        vshError(ctl, "%s", _("unable to determine if checkpoint has parent"));
    } else {
        vshResetLibvirtError();
    }
    return ret;
}


/*
 * "checkpoint-info" command
 */
static const vshCmdInfo info_checkpoint_info[] = {
    {.name = "help",
     .data = N_("checkpoint information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about a checkpoint.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_info[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT),
    {.name = "checkpointname",
     .type = VSH_OT_STRING,
     .help = N_("checkpoint name"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = NULL}
};


static bool
cmdCheckpointInfo(vshControl *ctl,
                  const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    const char *name;
    g_autofree char *parent = NULL;
    int count;
    unsigned int flags;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), name);
    vshPrint(ctl, "%-15s %s\n", _("Domain:"), virDomainGetName(dom));

    if (virshGetCheckpointParent(ctl, checkpoint, &parent) < 0) {
        vshError(ctl, "%s",
                 _("unexpected problem querying checkpoint state"));
        return false;
    }
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), parent ? parent : "-");

    /* Children, Descendants.  */
    flags = 0;
    count = virDomainCheckpointListAllChildren(checkpoint, NULL, flags);
    if (count < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT) {
            vshResetLibvirtError();
            return true;
        }
        return false;
    }
    vshPrint(ctl, "%-15s %d\n", _("Children:"), count);
    flags = VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS;
    count = virDomainCheckpointListAllChildren(checkpoint, NULL, flags);
    if (count < 0)
        return false;
    vshPrint(ctl, "%-15s %d\n", _("Descendants:"), count);

    return true;
}


/* Helpers for collecting a list of checkpoints.  */
struct virshChk {
    virDomainCheckpointPtr chk;
    char *parent;
};
struct virshCheckpointList {
    struct virshChk *chks;
    int nchks;
};

static void
virshCheckpointListFree(struct virshCheckpointList *checkpointlist)
{
    size_t i;

    if (!checkpointlist)
        return;
    if (checkpointlist->chks) {
        for (i = 0; i < checkpointlist->nchks; i++) {
            virshDomainCheckpointFree(checkpointlist->chks[i].chk);
            g_free(checkpointlist->chks[i].parent);
        }
        g_free(checkpointlist->chks);
    }
    g_free(checkpointlist);
}


static int
virshChkSorter(const void *a,
               const void *b)
{
    const struct virshChk *sa = a;
    const struct virshChk *sb = b;

    if (sa->chk && !sb->chk)
        return -1;
    if (!sa->chk)
        return sb->chk != NULL;

    return vshStrcasecmp(virDomainCheckpointGetName(sa->chk),
                         virDomainCheckpointGetName(sb->chk));
}


/* Compute a list of checkpoints from DOM.  If FROM is provided, the
 * list is limited to descendants of the given checkpoint.  If FLAGS is
 * given, the list is filtered.  If TREE is specified, then all but
 * FROM or the roots will also have parent information.  */
static struct virshCheckpointList *
virshCheckpointListCollect(vshControl *ctl,
                           virDomainPtr dom,
                           virDomainCheckpointPtr from,
                           unsigned int orig_flags,
                           bool tree)
{
    size_t i;
    int count = -1;
    virDomainCheckpointPtr *chks;
    struct virshCheckpointList *checkpointlist = NULL;
    struct virshCheckpointList *ret = NULL;
    unsigned int flags = orig_flags;

    checkpointlist = g_new0(struct virshCheckpointList, 1);

    if (from)
        count = virDomainCheckpointListAllChildren(from, &chks, flags);
    else
        count = virDomainListAllCheckpoints(dom, &chks, flags);
    if (count < 0) {
        vshError(ctl, "%s",
                 _("unexpected problem querying checkpoints"));
        goto cleanup;
    }

    /* When mixing --from and --tree, we also want a copy of from
     * in the list, but with no parent for that one entry.  */
    if (from && tree)
        checkpointlist->chks = g_new0(struct virshChk, count + 1);
    else
        checkpointlist->chks = g_new0(struct virshChk, count);
    checkpointlist->nchks = count;
    for (i = 0; i < count; i++)
        checkpointlist->chks[i].chk = chks[i];
    VIR_FREE(chks);
    if (tree) {
        for (i = 0; i < count; i++) {
            if (virshGetCheckpointParent(ctl, checkpointlist->chks[i].chk,
                                         &checkpointlist->chks[i].parent) < 0)
                goto cleanup;
        }
        if (from) {
            checkpointlist->chks[checkpointlist->nchks++].chk = from;
            virDomainCheckpointRef(from);
        }
    }

    if (!(orig_flags & VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL) &&
        checkpointlist->chks)
        qsort(checkpointlist->chks, checkpointlist->nchks,
              sizeof(*checkpointlist->chks), virshChkSorter);

    ret = g_steal_pointer(&checkpointlist);

 cleanup:
    virshCheckpointListFree(checkpointlist);
    return ret;
}


static const char *
virshCheckpointListLookup(int id,
                          bool parent,
                          void *opaque)
{
    struct virshCheckpointList *checkpointlist = opaque;
    if (parent)
        return checkpointlist->chks[id].parent;
    return virDomainCheckpointGetName(checkpointlist->chks[id].chk);
}


/*
 * "checkpoint-list" command
 */
static const vshCmdInfo info_checkpoint_list[] = {
    {.name = "help",
     .data = N_("List checkpoints for a domain")
    },
    {.name = "desc",
     .data = N_("Checkpoint List")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_list[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT),
    {.name = "parent",
     .type = VSH_OT_BOOL,
     .help = N_("add a column showing parent checkpoint")
    },
    {.name = "roots",
     .type = VSH_OT_BOOL,
     .help = N_("list only checkpoints without parents")
    },
    {.name = "leaves",
     .type = VSH_OT_BOOL,
     .help = N_("list only checkpoints without children")
    },
    {.name = "no-leaves",
     .type = VSH_OT_BOOL,
     .help = N_("list only checkpoints that are not leaves (with children)")
    },
    {.name = "tree",
     .type = VSH_OT_BOOL,
     .help = N_("list checkpoints in a tree")
    },
    {.name = "from",
     .type = VSH_OT_STRING,
     .help = N_("limit list to children of given checkpoint"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = "descendants",
     .type = VSH_OT_BOOL,
     .help = N_("with --from, list all descendants")
    },
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list checkpoint names only")
    },
    {.name = "topological",
     .type = VSH_OT_BOOL,
     .help = N_("sort list topologically rather than by name"),
    },
    {.name = NULL}
};

static bool
cmdCheckpointList(vshControl *ctl,
                  const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    size_t i;
    virDomainCheckpointPtr checkpoint = NULL;
    long long creation_longlong;
    g_autoptr(GDateTime) then = NULL;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool name = vshCommandOptBool(cmd, "name");
    bool from = vshCommandOptBool(cmd, "from");
    bool parent = vshCommandOptBool(cmd, "parent");
    bool roots = vshCommandOptBool(cmd, "roots");
    const char *from_chk = NULL;
    g_autoptr(virshDomainCheckpoint) start = NULL;
    struct virshCheckpointList *checkpointlist = NULL;
    g_autoptr(vshTable) table = NULL;

    VSH_EXCLUSIVE_OPTIONS_VAR(tree, name);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, roots);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, from);

#define FILTER(option, flag) \
    do { \
        if (vshCommandOptBool(cmd, option)) { \
            if (tree) { \
                vshError(ctl, \
                         _("--%1$s and --tree are mutually exclusive"), \
                         option); \
                return false; \
            } \
            flags |= VIR_DOMAIN_CHECKPOINT_LIST_ ## flag; \
        } \
    } while (0)

    FILTER("leaves", LEAVES);
    FILTER("no-leaves", NO_LEAVES);
#undef FILTER

    if (vshCommandOptBool(cmd, "topological"))
        flags |= VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL;

    if (roots)
        flags |= VIR_DOMAIN_CHECKPOINT_LIST_ROOTS;

    if (vshCommandOptBool(cmd, "descendants")) {
        if (!from) {
            vshError(ctl, "%s",
                     _("--descendants requires --from"));
            return false;
        }
        flags |= VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (from &&
        virshLookupCheckpoint(ctl, cmd, "from", dom, &start, &from_chk) < 0)
        goto cleanup;

    if (!(checkpointlist = virshCheckpointListCollect(ctl, dom, start, flags,
                                                      tree)))
        goto cleanup;

    if (!tree && !name) {
        if (parent)
            table = vshTableNew(_("Name"), _("Creation Time"), _("Parent"),
                                NULL);
        else
            table = vshTableNew(_("Name"), _("Creation Time"), NULL);
        if (!table)
            goto cleanup;
    }

    if (tree) {
        for (i = 0; i < checkpointlist->nchks; i++) {
            if (!checkpointlist->chks[i].parent &&
                vshTreePrint(ctl, virshCheckpointListLookup, checkpointlist,
                             checkpointlist->nchks, i) < 0)
                goto cleanup;
        }
        ret = true;
        goto cleanup;
    }

    for (i = 0; i < checkpointlist->nchks; i++) {
        g_autofree gchar *thenstr = NULL;
        g_autoptr(xmlDoc) xml = NULL;
        g_autoptr(xmlXPathContext) ctxt = NULL;
        g_autofree char *parent_chk = NULL;
        g_autofree char *doc = NULL;
        const char *chk_name;

        checkpoint = checkpointlist->chks[i].chk;
        chk_name = virDomainCheckpointGetName(checkpoint);
        assert(chk_name);

        if (name) {
            /* just print the checkpoint name */
            vshPrint(ctl, "%s\n", chk_name);
            continue;
        }

        if (!(doc = virDomainCheckpointGetXMLDesc(checkpoint, 0)))
            continue;

        if (!(xml = virXMLParseStringCtxt(doc, _("(domain_checkpoint)"), &ctxt)))
            continue;

        if (parent)
            parent_chk = virXPathString("string(/domaincheckpoint/parent/name)",
                                        ctxt);

        if (virXPathLongLong("string(/domaincheckpoint/creationTime)", ctxt,
                             &creation_longlong) < 0)
            continue;

        then = g_date_time_new_from_unix_local(creation_longlong);
        thenstr = g_date_time_format(then, "%Y-%m-%d %H:%M:%S %z");

        if (parent) {
            if (vshTableRowAppend(table, chk_name, thenstr,
                                  NULLSTR_EMPTY(parent_chk), NULL) < 0)
                goto cleanup;
        } else {
            if (vshTableRowAppend(table, chk_name, thenstr, NULL) < 0)
                goto cleanup;
        }
    }

    if (table)
        vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    virshCheckpointListFree(checkpointlist);
    return ret;
}


/*
 * "checkpoint-dumpxml" command
 */
static const vshCmdInfo info_checkpoint_dumpxml[] = {
    {.name = "help",
     .data = N_("Dump XML for a domain checkpoint")
    },
    {.name = "desc",
     .data = N_("Checkpoint Dump XML")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_dumpxml[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT),
    {.name = "checkpointname",
     .type = VSH_OT_STRING,
     .help = N_("checkpoint name"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = "no-domain",
     .type = VSH_OT_BOOL,
     .help = N_("exclude <domain> from XML")
    },
    {.name = "size",
     .type = VSH_OT_BOOL,
     .help = N_("include backup size estimate in XML dump")
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
cmdCheckpointDumpXML(vshControl *ctl,
                     const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_SECURE;
    if (vshCommandOptBool(cmd, "no-domain"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN;
    if (vshCommandOptBool(cmd, "size"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_SIZE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        return false;

    if (!(xml = virDomainCheckpointGetXMLDesc(checkpoint, flags)))
        return false;

    return virshDumpXML(ctl, xml, "domain-checkpoint", xpath, wrap);
}


/*
 * "checkpoint-parent" command
 */
static const vshCmdInfo info_checkpoint_parent[] = {
    {.name = "help",
     .data = N_("Get the name of the parent of a checkpoint")
    },
    {.name = "desc",
     .data = N_("Extract the checkpoint's parent, if any")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_parent[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT),
    {.name = "checkpointname",
     .type = VSH_OT_STRING,
     .help = N_("find parent of checkpoint name"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdCheckpointParent(vshControl *ctl,
                    const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    g_autofree char *parent = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        return false;

    if (virshGetCheckpointParent(ctl, checkpoint, &parent) < 0)
        return false;
    if (!parent) {
        vshError(ctl, _("checkpoint '%1$s' has no parent"), name);
        return false;
    }

    vshPrint(ctl, "%s", parent);

    return true;
}


/*
 * "checkpoint-delete" command
 */
static const vshCmdInfo info_checkpoint_delete[] = {
    {.name = "help",
     .data = N_("Delete a domain checkpoint")
    },
    {.name = "desc",
     .data = N_("Checkpoint Delete")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_checkpoint_delete[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT |
                                 VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "checkpointname",
     .type = VSH_OT_STRING,
     .help = N_("checkpoint name"),
     .completer = virshCheckpointNameCompleter,
    },
    {.name = "children",
     .type = VSH_OT_BOOL,
     .help = N_("delete checkpoint and all children")
    },
    {.name = "children-only",
     .type = VSH_OT_BOOL,
     .help = N_("delete children but not checkpoint")
    },
    {.name = "metadata",
     .type = VSH_OT_BOOL,
     .help = N_("delete only libvirt metadata, leaving checkpoint contents behind")
    },
    {.name = NULL}
};

static bool
cmdCheckpointDelete(vshControl *ctl,
                    const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainCheckpoint) checkpoint = NULL;
    unsigned int flags = 0;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        return false;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN;
    if (vshCommandOptBool(cmd, "children-only"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY;
    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY;

    if (virDomainCheckpointDelete(checkpoint, flags) == 0) {
        if (flags & VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY)
            vshPrintExtra(ctl, _("Domain checkpoint %1$s children deleted\n"), name);
        else
            vshPrintExtra(ctl, _("Domain checkpoint %1$s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete checkpoint %1$s"), name);
        return false;
    }

    return true;
}


const vshCmdDef checkpointCmds[] = {
    {.name = "checkpoint-create",
     .handler = cmdCheckpointCreate,
     .opts = opts_checkpoint_create,
     .info = info_checkpoint_create,
     .flags = 0
    },
    {.name = "checkpoint-create-as",
     .handler = cmdCheckpointCreateAs,
     .opts = opts_checkpoint_create_as,
     .info = info_checkpoint_create_as,
     .flags = 0
    },
    {.name = "checkpoint-delete",
     .handler = cmdCheckpointDelete,
     .opts = opts_checkpoint_delete,
     .info = info_checkpoint_delete,
     .flags = 0
    },
    {.name = "checkpoint-dumpxml",
     .handler = cmdCheckpointDumpXML,
     .opts = opts_checkpoint_dumpxml,
     .info = info_checkpoint_dumpxml,
     .flags = 0
    },
    {.name = "checkpoint-edit",
     .handler = cmdCheckpointEdit,
     .opts = opts_checkpoint_edit,
     .info = info_checkpoint_edit,
     .flags = 0
    },
    {.name = "checkpoint-info",
     .handler = cmdCheckpointInfo,
     .opts = opts_checkpoint_info,
     .info = info_checkpoint_info,
     .flags = 0
    },
    {.name = "checkpoint-list",
     .handler = cmdCheckpointList,
     .opts = opts_checkpoint_list,
     .info = info_checkpoint_list,
     .flags = 0
    },
    {.name = "checkpoint-parent",
     .handler = cmdCheckpointParent,
     .opts = opts_checkpoint_parent,
     .info = info_checkpoint_parent,
     .flags = 0
    },
    {.name = NULL}
};
