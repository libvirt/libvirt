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
#include "virstring.h"
#include "virxml.h"
#include "conf/checkpoint_conf.h"
#include "vsh-table.h"

/* Helper for checkpoint-create and checkpoint-create-as */
static bool
virshCheckpointCreate(vshControl *ctl,
                      virDomainPtr dom,
                      const char *buffer,
                      unsigned int flags,
                      const char *from)
{
    bool ret = false;
    virDomainCheckpointPtr checkpoint;
    const char *name = NULL;

    checkpoint = virDomainCheckpointCreateXML(dom, buffer, flags);

    if (checkpoint == NULL)
        goto cleanup;

    name = virDomainCheckpointGetName(checkpoint);
    if (!name) {
        vshError(ctl, "%s", _("Could not get checkpoint name"));
        goto cleanup;
    }

    if (from)
        vshPrintExtra(ctl, _("Domain checkpoint %s created from '%s'"),
                      name, from);
    else
        vshPrintExtra(ctl, _("Domain checkpoint %s created"), name);

    ret = true;

 cleanup:
    virshDomainCheckpointFree(checkpoint);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "xmlfile",
     .type = VSH_OT_STRING,
     .help = N_("domain checkpoint XML")
    },
    {.name = "redefine",
     .type = VSH_OT_BOOL,
     .help = N_("redefine metadata for existing checkpoint")
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
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *from = NULL;
    char *buffer = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "redefine"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "xmlfile", &from) < 0)
        goto cleanup;
    if (!from) {
        buffer = g_strdup("<domaincheckpoint/>");
    } else {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            vshSaveLibvirtError();
            goto cleanup;
        }
    }

    ret = virshCheckpointCreate(ctl, dom, buffer, flags, from);

 cleanup:
    VIR_FREE(buffer);
    virshDomainFree(dom);

    return ret;
}


/*
 * "checkpoint-create-as" command
 */
static int
virshParseCheckpointDiskspec(vshControl *ctl,
                             virBufferPtr buf,
                             const char *str)
{
    int ret = -1;
    const char *name = NULL;
    const char *checkpoint = NULL;
    const char *bitmap = NULL;
    char **array = NULL;
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
        vshError(ctl, _("unable to parse diskspec: %s"), str);
    virStringListFree(array);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "name",
     .type = VSH_OT_STRING,
     .help = N_("name of checkpoint")
    },
    {.name = "description",
     .type = VSH_OT_STRING,
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
    virDomainPtr dom = NULL;
    bool ret = false;
    char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;

    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_CHECKPOINT_CREATE_QUIESCE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "description", &desc) < 0)
        goto cleanup;

    virBufferAddLit(&buf, "<domaincheckpoint>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", name);
    virBufferEscapeString(&buf, "<description>%s</description>\n", desc);

    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "<disks>\n");
        virBufferAdjustIndent(&buf, 2);
        while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
            if (virshParseCheckpointDiskspec(ctl, &buf, opt->data) < 0)
                goto cleanup;
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</disks>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domaincheckpoint>\n");

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    buffer = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s\n",  buffer);
        ret = true;
        goto cleanup;
    }

    ret = virshCheckpointCreate(ctl, dom, buffer, flags, NULL);

 cleanup:
    virBufferFreeAndReset(&buf);
    VIR_FREE(buffer);
    virshDomainFree(dom);

    return ret;
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
        vshError(ctl, _("--%s is required"), arg);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    virDomainPtr dom = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    virDomainCheckpointPtr edited = NULL;
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
                      _("Checkpoint %s XML configuration not changed.\n"), \
                      name); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    edited = virDomainCheckpointCreateXML(dom, doc_edited, define_flags)
#include "virsh-edit.c"

    edited_name = virDomainCheckpointGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrintExtra(ctl, _("Checkpoint %s edited.\n"), name);
    } else {
        unsigned int delete_flags = VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY;

        if (virDomainCheckpointDelete(edited, delete_flags) < 0) {
            vshReportError(ctl);
            vshError(ctl, _("Failed to clean up %s"), edited_name);
            goto cleanup;
        }
        vshError(ctl, _("Cannot rename checkpoint %s to %s"),
                 name, edited_name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    if (!ret && name)
        vshError(ctl, _("Failed to update %s"), name);
    virshDomainCheckpointFree(edited);
    virshDomainCheckpointFree(checkpoint);
    virshDomainFree(dom);
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
    virDomainCheckpointPtr parent = NULL;
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
    virshDomainCheckpointFree(parent);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    virDomainPtr dom;
    virDomainCheckpointPtr checkpoint = NULL;
    const char *name;
    char *parent = NULL;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    bool ret = false;
    int count;
    unsigned int flags;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        goto cleanup;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), name);
    vshPrint(ctl, "%-15s %s\n", _("Domain:"), virDomainGetName(dom));

    if (virshGetCheckpointParent(ctl, checkpoint, &parent) < 0) {
        vshError(ctl, "%s",
                 _("unexpected problem querying checkpoint state"));
        goto cleanup;
    }
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), parent ? parent : "-");

    /* Children, Descendants.  */
    flags = 0;
    count = virDomainCheckpointListAllChildren(checkpoint, NULL, flags);
    if (count < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT) {
            vshResetLibvirtError();
            ret = true;
        }
        goto cleanup;
    }
    vshPrint(ctl, "%-15s %d\n", _("Children:"), count);
    flags = VIR_DOMAIN_CHECKPOINT_LIST_DESCENDANTS;
    count = virDomainCheckpointListAllChildren(checkpoint, NULL, flags);
    if (count < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %d\n", _("Descendants:"), count);

    ret = true;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(xml);
    VIR_FREE(parent);
    virshDomainCheckpointFree(checkpoint);
    virshDomainFree(dom);
    return ret;
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
typedef struct virshCheckpointList *virshCheckpointListPtr;

static void
virshCheckpointListFree(virshCheckpointListPtr checkpointlist)
{
    size_t i;

    if (!checkpointlist)
        return;
    if (checkpointlist->chks) {
        for (i = 0; i < checkpointlist->nchks; i++) {
            virshDomainCheckpointFree(checkpointlist->chks[i].chk);
            VIR_FREE(checkpointlist->chks[i].parent);
        }
        VIR_FREE(checkpointlist->chks);
    }
    VIR_FREE(checkpointlist);
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
static virshCheckpointListPtr
virshCheckpointListCollect(vshControl *ctl,
                           virDomainPtr dom,
                           virDomainCheckpointPtr from,
                           unsigned int orig_flags,
                           bool tree)
{
    size_t i;
    char **names = NULL;
    int count = -1;
    virDomainCheckpointPtr *chks;
    virshCheckpointListPtr checkpointlist = vshMalloc(ctl,
                                                      sizeof(*checkpointlist));
    virshCheckpointListPtr ret = NULL;
    unsigned int flags = orig_flags;

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
    checkpointlist->chks = vshCalloc(ctl, count + (tree && from),
                                     sizeof(*checkpointlist->chks));
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

    if (!(orig_flags & VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL))
        qsort(checkpointlist->chks, checkpointlist->nchks,
              sizeof(*checkpointlist->chks), virshChkSorter);

    ret = checkpointlist;
    checkpointlist = NULL;

 cleanup:
    virshCheckpointListFree(checkpointlist);
    if (names && count > 0)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}


static const char *
virshCheckpointListLookup(int id,
                          bool parent,
                          void *opaque)
{
    virshCheckpointListPtr checkpointlist = opaque;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    size_t i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    long long creation_longlong;
    time_t creation_time_t;
    char timestr[100];
    struct tm time_info;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool name = vshCommandOptBool(cmd, "name");
    bool from = vshCommandOptBool(cmd, "from");
    bool parent = vshCommandOptBool(cmd, "parent");
    bool roots = vshCommandOptBool(cmd, "roots");
    const char *from_chk = NULL;
    char *parent_chk = NULL;
    virDomainCheckpointPtr start = NULL;
    virshCheckpointListPtr checkpointlist = NULL;
    vshTablePtr table = NULL;

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
                         _("--%s and --tree are mutually exclusive"), \
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
        const char *chk_name;

        /* free up memory from previous iterations of the loop */
        VIR_FREE(parent_chk);
        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(xml);
        VIR_FREE(doc);

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
        creation_time_t = creation_longlong;
        if (creation_time_t != creation_longlong) {
            vshError(ctl, "%s", _("time_t overflow"));
            continue;
        }
        localtime_r(&creation_time_t, &time_info);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z",
                 &time_info);

        if (parent) {
            if (vshTableRowAppend(table, chk_name, timestr,
                                  NULLSTR_EMPTY(parent_chk), NULL) < 0)
                goto cleanup;
        } else {
            if (vshTableRowAppend(table, chk_name, timestr, NULL) < 0)
                goto cleanup;
        }
    }

    if (table)
        vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    /* this frees up memory from the last iteration of the loop */
    virshCheckpointListFree(checkpointlist);
    VIR_FREE(parent_chk);
    virshDomainCheckpointFree(start);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(doc);
    virshDomainFree(dom);
    vshTableFree(table);

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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    {.name = NULL}
};

static bool
cmdCheckpointDumpXML(vshControl *ctl,
                     const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_SECURE;
    if (vshCommandOptBool(cmd, "no-domain"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN;
    if (vshCommandOptBool(cmd, "size"))
        flags |= VIR_DOMAIN_CHECKPOINT_XML_SIZE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        goto cleanup;

    if (!(xml = virDomainCheckpointGetXMLDesc(checkpoint, flags)))
        goto cleanup;

    vshPrint(ctl, "%s", xml);
    ret = true;

 cleanup:
    VIR_FREE(xml);
    virshDomainCheckpointFree(checkpoint);
    virshDomainFree(dom);

    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    char *parent = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        goto cleanup;

    if (virshGetCheckpointParent(ctl, checkpoint, &parent) < 0)
        goto cleanup;
    if (!parent) {
        vshError(ctl, _("checkpoint '%s' has no parent"), name);
        goto cleanup;
    }

    vshPrint(ctl, "%s", parent);

    ret = true;

 cleanup:
    VIR_FREE(parent);
    virshDomainCheckpointFree(checkpoint);
    virshDomainFree(dom);

    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
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
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainCheckpointPtr checkpoint = NULL;
    unsigned int flags = 0;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (virshLookupCheckpoint(ctl, cmd, "checkpointname", dom,
                              &checkpoint, &name) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN;
    if (vshCommandOptBool(cmd, "children-only"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY;
    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_CHECKPOINT_DELETE_METADATA_ONLY;

    if (virDomainCheckpointDelete(checkpoint, flags) == 0) {
        if (flags & VIR_DOMAIN_CHECKPOINT_DELETE_CHILDREN_ONLY)
            vshPrintExtra(ctl, _("Domain checkpoint %s children deleted\n"), name);
        else
            vshPrintExtra(ctl, _("Domain checkpoint %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete checkpoint %s"), name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    virshDomainCheckpointFree(checkpoint);
    virshDomainFree(dom);

    return ret;
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
