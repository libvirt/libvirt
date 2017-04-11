/*
 * virsh-snapshot.c: Commands to manage domain snapshot
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
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>
#include "virsh-snapshot.h"

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
#include "conf/snapshot_conf.h"

#define VIRSH_COMMON_OPT_DOMAIN_FULL                       \
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name, id or uuid")) \

/* Helper for snapshot-create and snapshot-create-as */
static bool
virshSnapshotCreate(vshControl *ctl, virDomainPtr dom, const char *buffer,
                    unsigned int flags, const char *from)
{
    bool ret = false;
    virDomainSnapshotPtr snapshot;
    bool halt = false;
    char *doc = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    const char *name = NULL;

    snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);

    /* Emulate --halt on older servers.  */
    if (!snapshot && last_error->code == VIR_ERR_INVALID_ARG &&
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        int persistent;

        vshResetLibvirtError();
        persistent = virDomainIsPersistent(dom);
        if (persistent < 0) {
            vshReportError(ctl);
            goto cleanup;
        }
        if (!persistent) {
            vshError(ctl, "%s",
                     _("cannot halt after snapshot of transient domain"));
            goto cleanup;
        }
        if (virDomainIsActive(dom) == 1)
            halt = true;
        flags &= ~VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
        snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);
    }

    if (snapshot == NULL)
        goto cleanup;

    if (halt && virDomainDestroy(dom) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    name = virDomainSnapshotGetName(snapshot);
    if (!name) {
        vshError(ctl, "%s", _("Could not get snapshot name"));
        goto cleanup;
    }

    if (from)
        vshPrintExtra(ctl, _("Domain snapshot %s created from '%s'"), name, from);
    else
        vshPrintExtra(ctl, _("Domain snapshot %s created"), name);

    ret = true;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    VIR_FREE(doc);
    return ret;
}

/*
 * "snapshot-create" command
 */
static const vshCmdInfo info_snapshot_create[] = {
    {.name = "help",
     .data = N_("Create a snapshot from XML")
    },
    {.name = "desc",
     .data = N_("Create a snapshot (disk and RAM) from XML")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_create[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "xmlfile",
     .type = VSH_OT_STRING,
     .help = N_("domain snapshot XML")
    },
    {.name = "redefine",
     .type = VSH_OT_BOOL,
     .help = N_("redefine metadata for existing snapshot")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("with redefine, set current snapshot")),
    {.name = "no-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("take snapshot but create no metadata")
    },
    {.name = "halt",
     .type = VSH_OT_BOOL,
     .help = N_("halt domain after snapshot is created")
    },
    {.name = "disk-only",
     .type = VSH_OT_BOOL,
     .help = N_("capture disk state but not vm state")
    },
    {.name = "reuse-external",
     .type = VSH_OT_BOOL,
     .help = N_("reuse any existing external files")
    },
    {.name = "quiesce",
     .type = VSH_OT_BOOL,
     .help = N_("quiesce guest's file systems")
    },
    {.name = "atomic",
     .type = VSH_OT_BOOL,
     .help = N_("require atomic operation")
    },
    VIRSH_COMMON_OPT_LIVE(N_("take a live snapshot")),
    {.name = NULL}
};

static bool
cmdSnapshotCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *from = NULL;
    char *buffer = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "redefine"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    if (vshCommandOptBool(cmd, "current"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;
    if (vshCommandOptBool(cmd, "no-metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA;
    if (vshCommandOptBool(cmd, "halt"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
    if (vshCommandOptBool(cmd, "disk-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE;
    if (vshCommandOptBool(cmd, "atomic"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC;
    if (vshCommandOptBool(cmd, "live"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "xmlfile", &from) < 0)
        goto cleanup;
    if (!from) {
        buffer = vshStrdup(ctl, "<domainsnapshot/>");
    } else {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            vshSaveLibvirtError();
            goto cleanup;
        }
    }

    ret = virshSnapshotCreate(ctl, dom, buffer, flags, from);

 cleanup:
    VIR_FREE(buffer);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-create-as" command
 */
static int
virshParseSnapshotMemspec(vshControl *ctl, virBufferPtr buf, const char *str)
{
    int ret = -1;
    const char *snapshot = NULL;
    const char *file = NULL;
    char **array = NULL;
    int narray;
    size_t i;

    if (!str)
        return 0;

    narray = vshStringToArray(str, &array);
    if (narray < 0)
        goto cleanup;

    for (i = 0; i < narray; i++) {
        if (!snapshot && STRPREFIX(array[i], "snapshot="))
            snapshot = array[i] + strlen("snapshot=");
        else if (!file && STRPREFIX(array[i], "file="))
            file = array[i] + strlen("file=");
        else if (!file && *array[i] == '/')
            file = array[i];
        else
            goto cleanup;
    }

    virBufferAddLit(buf, "<memory");
    virBufferEscapeString(buf, " snapshot='%s'", snapshot);
    virBufferEscapeString(buf, " file='%s'", file);
    virBufferAddLit(buf, "/>\n");
    ret = 0;
 cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse memspec: %s"), str);
    virStringListFree(array);
    return ret;
}

static int
virshParseSnapshotDiskspec(vshControl *ctl, virBufferPtr buf, const char *str)
{
    int ret = -1;
    const char *name = NULL;
    const char *snapshot = NULL;
    const char *driver = NULL;
    const char *file = NULL;
    char **array = NULL;
    int narray;
    size_t i;

    narray = vshStringToArray(str, &array);
    if (narray <= 0)
        goto cleanup;

    name = array[0];
    for (i = 1; i < narray; i++) {
        if (!snapshot && STRPREFIX(array[i], "snapshot="))
            snapshot = array[i] + strlen("snapshot=");
        else if (!driver && STRPREFIX(array[i], "driver="))
            driver = array[i] + strlen("driver=");
        else if (!file && STRPREFIX(array[i], "file="))
            file = array[i] + strlen("file=");
        else
            goto cleanup;
    }

    virBufferEscapeString(buf, "<disk name='%s'", name);
    if (snapshot)
        virBufferAsprintf(buf, " snapshot='%s'", snapshot);
    if (driver || file) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        if (driver)
            virBufferAsprintf(buf, "<driver type='%s'/>\n", driver);
        if (file)
            virBufferEscapeString(buf, "<source file='%s'/>\n", file);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</disk>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    ret = 0;
 cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse diskspec: %s"), str);
    virStringListFree(array);
    return ret;
}

static const vshCmdInfo info_snapshot_create_as[] = {
    {.name = "help",
     .data = N_("Create a snapshot from a set of args")
    },
    {.name = "desc",
     .data = N_("Create a snapshot (disk and RAM) from arguments")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_create_as[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "name",
     .type = VSH_OT_STRING,
     .help = N_("name of snapshot")
    },
    {.name = "description",
     .type = VSH_OT_STRING,
     .help = N_("description of snapshot")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than create")
    },
    {.name = "no-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("take snapshot but create no metadata")
    },
    {.name = "halt",
     .type = VSH_OT_BOOL,
     .help = N_("halt domain after snapshot is created")
    },
    {.name = "disk-only",
     .type = VSH_OT_BOOL,
     .help = N_("capture disk state but not vm state")
    },
    {.name = "reuse-external",
     .type = VSH_OT_BOOL,
     .help = N_("reuse any existing external files")
    },
    {.name = "quiesce",
     .type = VSH_OT_BOOL,
     .help = N_("quiesce guest's file systems")
    },
    {.name = "atomic",
     .type = VSH_OT_BOOL,
     .help = N_("require atomic operation")
    },
    VIRSH_COMMON_OPT_LIVE(N_("take a live snapshot")),
    {.name = "memspec",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("memory attributes: [file=]name[,snapshot=type]")
    },
    {.name = "diskspec",
     .type = VSH_OT_ARGV,
     .help = N_("disk attributes: disk[,snapshot=type][,driver=type][,file=name]")
    },
    {.name = NULL}
};

static bool
cmdSnapshotCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    const char *memspec = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;

    if (vshCommandOptBool(cmd, "no-metadata")) {
        if (vshCommandOptBool(cmd, "print-xml")) {
            vshError(ctl, "%s",
                     _("--print-xml is incompatible with --no-metadata"));
            return false;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA;
    }
    if (vshCommandOptBool(cmd, "halt"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
    if (vshCommandOptBool(cmd, "disk-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE;
    if (vshCommandOptBool(cmd, "atomic"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC;
    if (vshCommandOptBool(cmd, "live"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "description", &desc) < 0)
        goto cleanup;

    virBufferAddLit(&buf, "<domainsnapshot>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", name);
    virBufferEscapeString(&buf, "<description>%s</description>\n", desc);

    if (vshCommandOptStringReq(ctl, cmd, "memspec", &memspec) < 0)
        goto cleanup;

    if (memspec && virshParseSnapshotMemspec(ctl, &buf, memspec) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "<disks>\n");
        virBufferAdjustIndent(&buf, 2);
        while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
            if (virshParseSnapshotDiskspec(ctl, &buf, opt->data) < 0)
                goto cleanup;
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</disks>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domainsnapshot>\n");

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

    ret = virshSnapshotCreate(ctl, dom, buffer, flags, NULL);

 cleanup:
    virBufferFreeAndReset(&buf);
    VIR_FREE(buffer);
    virDomainFree(dom);

    return ret;
}

/* Helper for resolving {--current | --ARG name} into a snapshot
 * belonging to DOM.  If EXCLUSIVE, fail if both --current and arg are
 * present.  On success, populate *SNAP and *NAME, before returning 0.
 * On failure, return -1 after issuing an error message.  */
static int
virshLookupSnapshot(vshControl *ctl, const vshCmd *cmd,
                    const char *arg, bool exclusive, virDomainPtr dom,
                    virDomainSnapshotPtr *snap, const char **name)
{
    bool current = vshCommandOptBool(cmd, "current");
    const char *snapname = NULL;

    if (vshCommandOptStringReq(ctl, cmd, arg, &snapname) < 0)
        return -1;

    if (exclusive && current && snapname) {
        vshError(ctl, _("--%s and --current are mutually exclusive"), arg);
        return -1;
    }

    if (snapname) {
        *snap = virDomainSnapshotLookupByName(dom, snapname, 0);
    } else if (current) {
        *snap = virDomainSnapshotCurrent(dom, 0);
    } else {
        vshError(ctl, _("--%s or --current is required"), arg);
        return -1;
    }
    if (!*snap) {
        vshReportError(ctl);
        return -1;
    }

    *name = virDomainSnapshotGetName(*snap);
    return 0;
}

/*
 * "snapshot-edit" command
 */
static const vshCmdInfo info_snapshot_edit[] = {
    {.name = "help",
     .data = N_("edit XML for a snapshot")
    },
    {.name = "desc",
     .data = N_("Edit the domain snapshot XML for a named snapshot")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_edit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("also set edited snapshot as current")),
    {.name = "rename",
     .type = VSH_OT_BOOL,
     .help = N_("allow renaming an existing snapshot")
    },
    {.name = "clone",
     .type = VSH_OT_BOOL,
     .help = N_("allow cloning to new name")
    },
    {.name = NULL}
};

static bool
cmdSnapshotEdit(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virDomainSnapshotPtr edited = NULL;
    const char *name = NULL;
    const char *edited_name;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    bool rename_okay = vshCommandOptBool(cmd, "rename");
    bool clone_okay = vshCommandOptBool(cmd, "clone");

    VSH_EXCLUSIVE_OPTIONS_EXPR("rename", rename_okay, "clone", clone_okay)

    if (vshCommandOptBool(cmd, "current") &&
        vshCommandOptBool(cmd, "snapshotname"))
        define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", false, dom,
                            &snapshot, &name) < 0)
        goto cleanup;

#define EDIT_GET_XML \
    virDomainSnapshotGetXMLDesc(snapshot, getxml_flags)
#define EDIT_NOT_CHANGED                                                     \
    do {                                                                     \
        /* Depending on flags, we re-edit even if XML is unchanged.  */      \
        if (!(define_flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) {          \
            vshPrintExtra(ctl,                                               \
                          _("Snapshot %s XML configuration not changed.\n"), \
                          name);                                             \
            ret = true;                                                      \
            goto edit_cleanup;                                               \
        }                                                                    \
    } while (0)
#define EDIT_DEFINE \
    (strstr(doc, "<state>disk-snapshot</state>") ? \
    define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY : 0), \
    edited = virDomainSnapshotCreateXML(dom, doc_edited, define_flags)
#include "virsh-edit.c"

    edited_name = virDomainSnapshotGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrintExtra(ctl, _("Snapshot %s edited.\n"), name);
    } else if (clone_okay) {
        vshPrintExtra(ctl, _("Snapshot %s cloned to %s.\n"), name,
                      edited_name);
    } else {
        unsigned int delete_flags;

        delete_flags = VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;
        if (virDomainSnapshotDelete(rename_okay ? snapshot : edited,
                                    delete_flags) < 0) {
            vshReportError(ctl);
            vshError(ctl, _("Failed to clean up %s"),
                     rename_okay ? name : edited_name);
            goto cleanup;
        }
        if (!rename_okay) {
            vshError(ctl, _("Must use --rename or --clone to change %s to %s"),
                     name, edited_name);
            goto cleanup;
        }
    }

    ret = true;

 cleanup:
    if (!ret && name)
        vshError(ctl, _("Failed to update %s"), name);
    if (edited)
        virDomainSnapshotFree(edited);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);
    return ret;
}

/*
 * "snapshot-current" command
 */
static const vshCmdInfo info_snapshot_current[] = {
    {.name = "help",
     .data = N_("Get or set the current snapshot")
    },
    {.name = "desc",
     .data = N_("Get or set the current snapshot")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_current[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list the name, rather than the full xml")
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("name of existing snapshot to make current")
    },
    {.name = NULL}
};

static bool
cmdSnapshotCurrent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    int current;
    virDomainSnapshotPtr snapshot = NULL;
    char *xml = NULL;
    const char *snapshotname = NULL;
    unsigned int flags = 0;
    const char *domname;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    VSH_EXCLUSIVE_OPTIONS("name", "snapshotname");

    if (!(dom = virshCommandOptDomain(ctl, cmd, &domname)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "snapshotname", &snapshotname) < 0)
        goto cleanup;

    if (snapshotname) {
        virDomainSnapshotPtr snapshot2 = NULL;
        flags = (VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                 VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT);

        if (!(snapshot = virDomainSnapshotLookupByName(dom, snapshotname, 0)))
            goto cleanup;

        xml = virDomainSnapshotGetXMLDesc(snapshot, VIR_DOMAIN_XML_SECURE);
        if (!xml)
            goto cleanup;

        /* strstr is safe here, since xml came from libvirt API and not user */
        if (strstr(xml, "<state>disk-snapshot</state>"))
            flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;

        if (!(snapshot2 = virDomainSnapshotCreateXML(dom, xml, flags)))
            goto cleanup;

        virDomainSnapshotFree(snapshot2);
        vshPrintExtra(ctl, _("Snapshot %s set as current"), snapshotname);
        ret = true;
        goto cleanup;
    }

    if ((current = virDomainHasCurrentSnapshot(dom, 0)) < 0)
        goto cleanup;

    if (!current) {
        vshError(ctl, _("domain '%s' has no current snapshot"), domname);
        goto cleanup;
    } else {
        if (!(snapshot = virDomainSnapshotCurrent(dom, 0)))
            goto cleanup;

        if (vshCommandOptBool(cmd, "name")) {
            const char *name;
            if (!(name = virDomainSnapshotGetName(snapshot)))
                goto cleanup;

            vshPrint(ctl, "%s", name);
        } else {
            if (!(xml = virDomainSnapshotGetXMLDesc(snapshot, flags)))
                goto cleanup;

            vshPrint(ctl, "%s", xml);
        }
    }

    ret = true;

 cleanup:
    if (!ret)
        vshReportError(ctl);
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);

    return ret;
}

/* Helper function to get the name of a snapshot's parent.  Caller
 * must free the result.  Returns 0 on success (including when it was
 * proven no parent exists), and -1 on failure with error reported
 * (such as no snapshot support or domain deleted in meantime).  */
static int
virshGetSnapshotParent(vshControl *ctl, virDomainSnapshotPtr snapshot,
                       char **parent_name)
{
    virDomainSnapshotPtr parent = NULL;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;
    virshControlPtr priv = ctl->privData;

    *parent_name = NULL;

    /* Try new API, since it is faster. */
    if (!priv->useSnapshotOld) {
        parent = virDomainSnapshotGetParent(snapshot, 0);
        if (parent) {
            /* API works, and virDomainSnapshotGetName will succeed */
            *parent_name = vshStrdup(ctl, virDomainSnapshotGetName(parent));
            ret = 0;
            goto cleanup;
        }
        if (last_error->code == VIR_ERR_NO_DOMAIN_SNAPSHOT) {
            /* API works, and we found a root with no parent */
            ret = 0;
            goto cleanup;
        }
        /* API didn't work, fall back to XML scraping. */
        priv->useSnapshotOld = true;
    }

    xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    *parent_name = virXPathString("string(/domainsnapshot/parent/name)", ctxt);
    ret = 0;

 cleanup:
    if (ret < 0) {
        vshReportError(ctl);
        vshError(ctl, "%s", _("unable to determine if snapshot has parent"));
    } else {
        vshResetLibvirtError();
    }
    if (parent)
        virDomainSnapshotFree(parent);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(xml);
    return ret;
}

/* Helper function to filter snapshots according to status and
 * location portion of flags.  Returns 0 if filter excluded snapshot,
 * 1 if snapshot is okay (or if snapshot is already NULL), and -1 on
 * failure, with error already reported.  */
static int
virshSnapshotFilter(vshControl *ctl, virDomainSnapshotPtr snapshot,
                    unsigned int flags)
{
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;
    char *state = NULL;

    if (!snapshot)
        return 1;

    xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    /* Libvirt 1.0.1 and newer never call this function, because the
     * filtering is already supported by the listing functions.  Older
     * libvirt lacked /domainsnapshot/memory, but was also limited in
     * the types of snapshots it could create: if state was disk-only,
     * the snapshot is external; all other snapshots are internal.  */
    state = virXPathString("string(/domainsnapshot/state)", ctxt);
    if (!state) {
        vshError(ctl, "%s", _("unable to perform snapshot filtering"));
        goto cleanup;
    }
    if (STREQ(state, "disk-snapshot")) {
        ret = ((flags & (VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY |
                         VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL)) ==
               (VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY |
                VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL));
    } else {
        if (!(flags & VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL))
            ret = 0;
        else if (STREQ(state, "shutoff"))
            ret = !!(flags & VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE);
        else
            ret = !!(flags & VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE);
    }

 cleanup:
    VIR_FREE(state);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(xml);
    return ret;
}

/*
 * "snapshot-info" command
 */
static const vshCmdInfo info_snapshot_info[] = {
    {.name = "help",
     .data = N_("snapshot information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about a snapshot.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_info[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("info on current snapshot")),
    {.name = NULL}
};

static bool
cmdSnapshotInfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainSnapshotPtr snapshot = NULL;
    const char *name;
    char *doc = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *state = NULL;
    int external;
    char *parent = NULL;
    bool ret = false;
    int count;
    unsigned int flags;
    int current;
    int metadata;
    virshControlPtr priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        goto cleanup;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), name);
    vshPrint(ctl, "%-15s %s\n", _("Domain:"), virDomainGetName(dom));

    /* Determine if snapshot is current; this is useful enough that we
     * attempt a fallback.  */
    current = virDomainSnapshotIsCurrent(snapshot, 0);
    if (current < 0) {
        virDomainSnapshotPtr other = virDomainSnapshotCurrent(dom, 0);

        vshResetLibvirtError();
        current = 0;
        if (other) {
            if (STREQ(name, virDomainSnapshotGetName(other)))
                current = 1;
            virDomainSnapshotFree(other);
        }
    }
    vshPrint(ctl, "%-15s %s\n", _("Current:"),
             current > 0 ? _("yes") : _("no"));

    /* Get the XML configuration of the snapshot to determine the
     * state of the machine at the time of the snapshot.  */
    doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!doc)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    state = virXPathString("string(/domainsnapshot/state)", ctxt);
    if (!state) {
        vshError(ctl, "%s",
                 _("unexpected problem reading snapshot xml"));
        goto cleanup;
    }
    vshPrint(ctl, "%-15s %s\n", _("State:"), state);

    /* In addition to state, location is useful.  If the snapshot has
     * a <memory> element, then the existence of snapshot='external'
     * prior to <domain> is the deciding factor; for snapshots
     * created prior to 1.0.1, a state of disk-only is the only
     * external snapshot.  */
    switch (virXPathBoolean("boolean(/domainsnapshot/memory)", ctxt)) {
    case 1:
        external = virXPathBoolean("boolean(/domainsnapshot/memory[@snapshot='external'] "
                                   "| /domainsnapshot/disks/disk[@snapshot='external'])",
                                   ctxt);
        break;
    case 0:
        external = STREQ(state, "disk-snapshot");
        break;
    default:
        external = -1;
        break;

    }
    if (external < 0) {
        vshError(ctl, "%s",
                 _("unexpected problem reading snapshot xml"));
        goto cleanup;
    }
    vshPrint(ctl, "%-15s %s\n", _("Location:"),
             external ? _("external") : _("internal"));

    /* Since we already have the XML, there's no need to call
     * virDomainSnapshotGetParent */
    parent = virXPathString("string(/domainsnapshot/parent/name)", ctxt);
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), parent ? parent : "-");

    /* Children, Descendants.  After this point, the fallback to
     * compute children is too expensive, so we gracefully quit if the
     * APIs don't exist.  */
    if (priv->useSnapshotOld) {
        ret = true;
        goto cleanup;
    }
    flags = 0;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT) {
            vshResetLibvirtError();
            ret = true;
        }
        goto cleanup;
    }
    vshPrint(ctl, "%-15s %d\n", _("Children:"), count);
    flags = VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %d\n", _("Descendants:"), count);

    /* Metadata; the fallback here relies on the fact that metadata
     * used to have an all-or-nothing effect on snapshot count.  */
    metadata = virDomainSnapshotHasMetadata(snapshot, 0);
    if (metadata < 0) {
        metadata = virDomainSnapshotNum(dom,
                                        VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
        vshResetLibvirtError();
    }
    if (metadata >= 0)
        vshPrint(ctl, "%-15s %s\n", _("Metadata:"),
                 metadata ? _("yes") : _("no"));

    ret = true;

 cleanup:
    VIR_FREE(state);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(doc);
    VIR_FREE(parent);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);
    return ret;
}

/* Helpers for collecting a list of snapshots.  */
struct virshSnap {
    virDomainSnapshotPtr snap;
    char *parent;
};
struct virshSnapshotList {
    struct virshSnap *snaps;
    int nsnaps;
};
typedef struct virshSnapshotList *virshSnapshotListPtr;

static void
virshSnapshotListFree(virshSnapshotListPtr snaplist)
{
    size_t i;

    if (!snaplist)
        return;
    if (snaplist->snaps) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            if (snaplist->snaps[i].snap)
                virDomainSnapshotFree(snaplist->snaps[i].snap);
            VIR_FREE(snaplist->snaps[i].parent);
        }
        VIR_FREE(snaplist->snaps);
    }
    VIR_FREE(snaplist);
}

static int
virshSnapSorter(const void *a, const void *b)
{
    const struct virshSnap *sa = a;
    const struct virshSnap *sb = b;

    if (sa->snap && !sb->snap)
        return -1;
    if (!sa->snap)
        return sb->snap != NULL;

    return vshStrcasecmp(virDomainSnapshotGetName(sa->snap),
                         virDomainSnapshotGetName(sb->snap));
}

/* Compute a list of snapshots from DOM.  If FROM is provided, the
 * list is limited to descendants of the given snapshot.  If FLAGS is
 * given, the list is filtered.  If TREE is specified, then all but
 * FROM or the roots will also have parent information.  */
static virshSnapshotListPtr
virshSnapshotListCollect(vshControl *ctl, virDomainPtr dom,
                         virDomainSnapshotPtr from,
                         unsigned int orig_flags, bool tree)
{
    size_t i;
    char **names = NULL;
    int count = -1;
    bool descendants = false;
    bool roots = false;
    virDomainSnapshotPtr *snaps;
    virshSnapshotListPtr snaplist = vshMalloc(ctl, sizeof(*snaplist));
    virshSnapshotListPtr ret = NULL;
    const char *fromname = NULL;
    int start_index = -1;
    int deleted = 0;
    bool filter_fallback = false;
    unsigned int flags = orig_flags;
    virshControlPtr priv = ctl->privData;

    /* Try the interface available in 0.9.13 and newer.  */
    if (!priv->useSnapshotOld) {
        if (from)
            count = virDomainSnapshotListAllChildren(from, &snaps, flags);
        else
            count = virDomainListAllSnapshots(dom, &snaps, flags);
        /* If we failed because of flags added in 1.0.1, we can do
         * fallback filtering. */
        if  (count < 0 && last_error->code == VIR_ERR_INVALID_ARG &&
             flags & (VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS |
                      VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)) {
            flags &= ~(VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS |
                       VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION);
            vshResetLibvirtError();
            filter_fallback = true;
            if (from)
                count = virDomainSnapshotListAllChildren(from, &snaps, flags);
            else
                count = virDomainListAllSnapshots(dom, &snaps, flags);
        }
    }
    if (count >= 0) {
        /* When mixing --from and --tree, we also want a copy of from
         * in the list, but with no parent for that one entry.  */
        snaplist->snaps = vshCalloc(ctl, count + (tree && from),
                                    sizeof(*snaplist->snaps));
        snaplist->nsnaps = count;
        for (i = 0; i < count; i++)
            snaplist->snaps[i].snap = snaps[i];
        VIR_FREE(snaps);
        if (tree) {
            for (i = 0; i < count; i++) {
                if (virshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
                                           &snaplist->snaps[i].parent) < 0)
                    goto cleanup;
            }
            if (from) {
                snaplist->snaps[snaplist->nsnaps++].snap = from;
                virDomainSnapshotRef(from);
            }
        }
        goto success;
    }

    /* Assume that if we got this far, then the --no-leaves and
     * --no-metadata flags were not supported.  Disable groups that
     * have no impact.  */
    /* XXX should we emulate --no-leaves?  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES &&
        flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES)
        flags &= ~(VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES |
                   VIR_DOMAIN_SNAPSHOT_LIST_LEAVES);
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA &&
        flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA)
        flags &= ~(VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA |
                   VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA) {
        /* We can emulate --no-metadata if --metadata was supported,
         * since it was an all-or-none attribute on old servers.  */
        count = virDomainSnapshotNum(dom,
                                     VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
        if (count < 0)
            goto cleanup;
        if (count > 0)
            return snaplist;
        flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA;
    }
    if (flags & (VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS |
                 VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)) {
        flags &= ~(VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS |
                   VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION);
        filter_fallback = true;
    }

    /* This uses the interfaces available in 0.8.0-0.9.6
     * (virDomainSnapshotListNames, global list only) and in
     * 0.9.7-0.9.12 (addition of virDomainSnapshotListChildrenNames
     * for child listing, and new flags), as follows, with [*] by the
     * combinations that need parent info (either for filtering
     * purposes or for the resulting tree listing):
     *                              old               new
     * list                         global as-is      global as-is
     * list --roots                *global + filter   global + flags
     * list --from                 *global + filter   child as-is
     * list --from --descendants   *global + filter   child + flags
     * list --tree                 *global as-is     *global as-is
     * list --tree --from          *global + filter  *child + flags
     *
     * Additionally, when --tree and --from are both used, from is
     * added to the final list as the only element without a parent.
     * Otherwise, --from does not appear in the final list.
     */
    if (from) {
        fromname = virDomainSnapshotGetName(from);
        if (!fromname) {
            vshError(ctl, "%s", _("Could not get snapshot name"));
            goto cleanup;
        }
        descendants = (flags & VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS) || tree;
        if (tree)
            flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;

        /* Determine if we can use the new child listing API.  */
        if (priv->useSnapshotOld ||
            ((count = virDomainSnapshotNumChildren(from, flags)) < 0 &&
             last_error->code == VIR_ERR_NO_SUPPORT)) {
            /* We can emulate --from.  */
            /* XXX can we also emulate --leaves? */
            vshResetLibvirtError();
            priv->useSnapshotOld = true;
            flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
            goto global;
        }
        if (tree && count >= 0)
            count++;
    } else {
    global:
        /* Global listing (including fallback when --from failed with
         * child listing).  */
        count = virDomainSnapshotNum(dom, flags);

        /* Fall back to simulation if --roots was unsupported. */
        /* XXX can we also emulate --leaves? */
        if (!from && count < 0 && last_error->code == VIR_ERR_INVALID_ARG &&
            (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS)) {
            vshResetLibvirtError();
            roots = true;
            flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
            count = virDomainSnapshotNum(dom, flags);
        }
    }

    if (count < 0) {
        if (!last_error)
            vshError(ctl, _("failed to collect snapshot list"));
        goto cleanup;
    }

    if (!count)
        goto success;

    names = vshCalloc(ctl, sizeof(*names), count);

    /* Now that we have a count, collect the list.  */
    if (from && !priv->useSnapshotOld) {
        if (tree) {
            if (count)
                count = virDomainSnapshotListChildrenNames(from, names + 1,
                                                           count - 1, flags);
            if (count >= 0) {
                count++;
                names[0] = vshStrdup(ctl, fromname);
            }
        } else {
            count = virDomainSnapshotListChildrenNames(from, names,
                                                       count, flags);
        }
    } else {
        count = virDomainSnapshotListNames(dom, names, count, flags);
    }
    if (count < 0)
        goto cleanup;

    snaplist->snaps = vshCalloc(ctl, sizeof(*snaplist->snaps), count);
    snaplist->nsnaps = count;
    for (i = 0; i < count; i++) {
        snaplist->snaps[i].snap = virDomainSnapshotLookupByName(dom,
                                                                names[i], 0);
        if (!snaplist->snaps[i].snap)
            goto cleanup;
    }

    /* Collect parents when needed.  With the new API, --tree and
     * --from together put from as the first element without a parent;
     * with the old API we still need to do a post-process filtering
     * based on all parent information.  */
    if (tree || (from && priv->useSnapshotOld) || roots) {
        for (i = (from && !priv->useSnapshotOld); i < count; i++) {
            if (from && priv->useSnapshotOld && STREQ(names[i], fromname)) {
                start_index = i;
                if (tree)
                    continue;
            }
            if (virshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
                                       &snaplist->snaps[i].parent) < 0)
                goto cleanup;
            if ((from && ((tree && !snaplist->snaps[i].parent) ||
                          (!descendants &&
                           STRNEQ_NULLABLE(fromname,
                                           snaplist->snaps[i].parent)))) ||
                (roots && snaplist->snaps[i].parent)) {
                virDomainSnapshotFree(snaplist->snaps[i].snap);
                snaplist->snaps[i].snap = NULL;
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
            }
        }
    }
    if (tree)
        goto success;

    if (priv->useSnapshotOld && descendants) {
        bool changed = false;
        bool remaining = false;

        /* Make multiple passes over the list - first pass finds
         * direct children and NULLs out all roots and from, remaining
         * passes NULL out any undecided entry whose parent is not
         * still in list.  We mark known descendants by clearing
         * snaps[i].parents.  Sorry, this is O(n^3) - hope your
         * hierarchy isn't huge.  XXX Is it worth making O(n^2 log n)
         * by using qsort and bsearch?  */
        if (start_index < 0) {
            vshError(ctl, _("snapshot %s disappeared from list"), fromname);
            goto cleanup;
        }
        for (i = 0; i < count; i++) {
            if (i == start_index || !snaplist->snaps[i].parent) {
                VIR_FREE(names[i]);
                virDomainSnapshotFree(snaplist->snaps[i].snap);
                snaplist->snaps[i].snap = NULL;
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
            } else if (STREQ(snaplist->snaps[i].parent, fromname)) {
                VIR_FREE(snaplist->snaps[i].parent);
                changed = true;
            } else {
                remaining = true;
            }
        }
        if (!changed) {
            ret = vshMalloc(ctl, sizeof(*snaplist));
            goto cleanup;
        }
        while (changed && remaining) {
            changed = remaining = false;
            for (i = 0; i < count; i++) {
                bool found_parent = false;
                size_t j;

                if (!names[i] || !snaplist->snaps[i].parent)
                    continue;
                for (j = 0; j < count; j++) {
                    if (!names[j] || i == j)
                        continue;
                    if (STREQ(snaplist->snaps[i].parent, names[j])) {
                        found_parent = true;
                        if (!snaplist->snaps[j].parent)
                            VIR_FREE(snaplist->snaps[i].parent);
                        else
                            remaining = true;
                        break;
                    }
                }
                if (!found_parent) {
                    changed = true;
                    VIR_FREE(names[i]);
                    virDomainSnapshotFree(snaplist->snaps[i].snap);
                    snaplist->snaps[i].snap = NULL;
                    VIR_FREE(snaplist->snaps[i].parent);
                    deleted++;
                }
            }
        }
    }

 success:
    if (filter_fallback) {
        /* Older API didn't filter on status or location, but the
         * information is available in domain XML.  */
        if (!(orig_flags & VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS))
            orig_flags |= VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS;
        if (!(orig_flags & VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION))
            orig_flags |= VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION;
        for (i = 0; i < snaplist->nsnaps; i++) {
            switch (virshSnapshotFilter(ctl, snaplist->snaps[i].snap,
                                        orig_flags)) {
            case 1:
                break;
            case 0:
                virDomainSnapshotFree(snaplist->snaps[i].snap);
                snaplist->snaps[i].snap = NULL;
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
                break;
            default:
                goto cleanup;
            }
        }
    }
    qsort(snaplist->snaps, snaplist->nsnaps, sizeof(*snaplist->snaps),
          virshSnapSorter);
    snaplist->nsnaps -= deleted;

    ret = snaplist;
    snaplist = NULL;

 cleanup:
    virshSnapshotListFree(snaplist);
    if (names && count > 0)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}

static const char *
virshSnapshotListLookup(int id, bool parent, void *opaque)
{
    virshSnapshotListPtr snaplist = opaque;
    if (parent)
        return snaplist->snaps[id].parent;
    return virDomainSnapshotGetName(snaplist->snaps[id].snap);
}

/*
 * "snapshot-list" command
 */
static const vshCmdInfo info_snapshot_list[] = {
    {.name = "help",
     .data = N_("List snapshots for a domain")
    },
    {.name = "desc",
     .data = N_("Snapshot List")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_list[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "parent",
     .type = VSH_OT_BOOL,
     .help = N_("add a column showing parent snapshot")
    },
    {.name = "roots",
     .type = VSH_OT_BOOL,
     .help = N_("list only snapshots without parents")
    },
    {.name = "leaves",
     .type = VSH_OT_BOOL,
     .help = N_("list only snapshots without children")
    },
    {.name = "no-leaves",
     .type = VSH_OT_BOOL,
     .help = N_("list only snapshots that are not leaves (with children)")
    },
    {.name = "metadata",
     .type = VSH_OT_BOOL,
     .help = N_("list only snapshots that have metadata that would prevent undefine")
    },
    {.name = "no-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("list only snapshots that have no metadata managed by libvirt")
    },
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("filter by snapshots taken while inactive")
    },
    {.name = "active",
     .type = VSH_OT_BOOL,
     .help = N_("filter by snapshots taken while active (system checkpoints)")
    },
    {.name = "disk-only",
     .type = VSH_OT_BOOL,
     .help = N_("filter by disk-only snapshots")
    },
    {.name = "internal",
     .type = VSH_OT_BOOL,
     .help = N_("filter by internal snapshots")
    },
    {.name = "external",
     .type = VSH_OT_BOOL,
     .help = N_("filter by external snapshots")
    },
    {.name = "tree",
     .type = VSH_OT_BOOL,
     .help = N_("list snapshots in a tree")
    },
    {.name = "from",
     .type = VSH_OT_STRING,
     .help = N_("limit list to children of given snapshot")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("limit list to children of current snapshot")),
    {.name = "descendants",
     .type = VSH_OT_BOOL,
     .help = N_("with --from, list all descendants")
    },
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list snapshot names only")
    },

    {.name = NULL}
};

static bool
cmdSnapshotList(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    size_t i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *state = NULL;
    long long creation_longlong;
    time_t creation_time_t;
    char timestr[100];
    struct tm time_info;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool name = vshCommandOptBool(cmd, "name");
    bool from = vshCommandOptBool(cmd, "from");
    bool parent = vshCommandOptBool(cmd, "parent");
    bool roots = vshCommandOptBool(cmd, "roots");
    bool current = vshCommandOptBool(cmd, "current");
    const char *from_snap = NULL;
    char *parent_snap = NULL;
    virDomainSnapshotPtr start = NULL;
    virshSnapshotListPtr snaplist = NULL;

    VSH_EXCLUSIVE_OPTIONS_VAR(tree, name);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, roots);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, from);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, current);

#define FILTER(option, flag)                                          \
    do {                                                              \
        if (vshCommandOptBool(cmd, option)) {                         \
            if (tree) {                                               \
                vshError(ctl,                                         \
                         _("--%s and --tree are mutually exclusive"), \
                         option);                                     \
                return false;                                         \
            }                                                         \
            flags |= VIR_DOMAIN_SNAPSHOT_LIST_ ## flag;               \
        }                                                             \
    } while (0)

    FILTER("leaves", LEAVES);
    FILTER("no-leaves", NO_LEAVES);
    FILTER("inactive", INACTIVE);
    FILTER("active", ACTIVE);
    FILTER("disk-only", DISK_ONLY);
    FILTER("internal", INTERNAL);
    FILTER("external", EXTERNAL);
#undef FILTER

    if (roots)
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;

    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_METADATA;

    if (vshCommandOptBool(cmd, "no-metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA;

    if (vshCommandOptBool(cmd, "descendants")) {
        if (!from && !current) {
            vshError(ctl, "%s",
                     _("--descendants requires either --from or --current"));
            return false;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((from || current) &&
        virshLookupSnapshot(ctl, cmd, "from", true, dom, &start, &from_snap) < 0)
        goto cleanup;

    if (!(snaplist = virshSnapshotListCollect(ctl, dom, start, flags, tree)))
        goto cleanup;

    if (!tree && !name) {
        if (parent)
            vshPrintExtra(ctl, " %-20s %-25s %-15s %s",
                          _("Name"), _("Creation Time"), _("State"),
                          _("Parent"));
        else
            vshPrintExtra(ctl, " %-20s %-25s %s",
                          _("Name"), _("Creation Time"), _("State"));
        vshPrintExtra(ctl, "\n"
                           "------------------------------"
                           "------------------------------\n");
    }

    if (tree) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            if (!snaplist->snaps[i].parent &&
                vshTreePrint(ctl, virshSnapshotListLookup, snaplist,
                             snaplist->nsnaps, i) < 0)
                goto cleanup;
        }
        ret = true;
        goto cleanup;
    }

    for (i = 0; i < snaplist->nsnaps; i++) {
        const char *snap_name;

        /* free up memory from previous iterations of the loop */
        VIR_FREE(parent_snap);
        VIR_FREE(state);
        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(xml);
        VIR_FREE(doc);

        snapshot = snaplist->snaps[i].snap;
        snap_name = virDomainSnapshotGetName(snapshot);
        assert(snap_name);

        if (name) {
            /* just print the snapshot name */
            vshPrint(ctl, "%s\n", snap_name);
            continue;
        }

        if (!(doc = virDomainSnapshotGetXMLDesc(snapshot, 0)))
            continue;

        if (!(xml = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt)))
            continue;

        if (parent)
            parent_snap = virXPathString("string(/domainsnapshot/parent/name)",
                                         ctxt);

        if (!(state = virXPathString("string(/domainsnapshot/state)", ctxt)))
            continue;

        if (virXPathLongLong("string(/domainsnapshot/creationTime)", ctxt,
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

        if (parent)
            vshPrint(ctl, " %-20s %-25s %-15s %s\n",
                     snap_name, timestr, state, parent_snap);
        else
            vshPrint(ctl, " %-20s %-25s %s\n", snap_name, timestr, state);
    }

    ret = true;

 cleanup:
    /* this frees up memory from the last iteration of the loop */
    virshSnapshotListFree(snaplist);
    VIR_FREE(parent_snap);
    VIR_FREE(state);
    if (start)
        virDomainSnapshotFree(start);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(doc);
    virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-dumpxml" command
 */
static const vshCmdInfo info_snapshot_dumpxml[] = {
    {.name = "help",
     .data = N_("Dump XML for a domain snapshot")
    },
    {.name = "desc",
     .data = N_("Snapshot Dump XML")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_dumpxml[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("snapshot name")
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = NULL}
};

static bool
cmdSnapshotDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "snapshotname", &name) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (!(snapshot = virDomainSnapshotLookupByName(dom, name, 0)))
        goto cleanup;

    if (!(xml = virDomainSnapshotGetXMLDesc(snapshot, flags)))
        goto cleanup;

    vshPrint(ctl, "%s", xml);
    ret = true;

 cleanup:
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-parent" command
 */
static const vshCmdInfo info_snapshot_parent[] = {
    {.name = "help",
     .data = N_("Get the name of the parent of a snapshot")
    },
    {.name = "desc",
     .data = N_("Extract the snapshot's parent, if any")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_parent[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("find parent of snapshot name")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("find parent of current snapshot")),
    {.name = NULL}
};

static bool
cmdSnapshotParent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *parent = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        goto cleanup;

    if (virshGetSnapshotParent(ctl, snapshot, &parent) < 0)
        goto cleanup;
    if (!parent) {
        vshError(ctl, _("snapshot '%s' has no parent"), name);
        goto cleanup;
    }

    vshPrint(ctl, "%s", parent);

    ret = true;

 cleanup:
    VIR_FREE(parent);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-revert" command
 */
static const vshCmdInfo info_snapshot_revert[] = {
    {.name = "help",
     .data = N_("Revert a domain to a snapshot")
    },
    {.name = "desc",
     .data = N_("Revert domain to snapshot")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_revert[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("revert to current snapshot")),
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("after reverting, change state to running")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("after reverting, change state to paused")
    },
    {.name = "force",
     .type = VSH_OT_BOOL,
     .help = N_("try harder on risky reverts")
    },
    {.name = NULL}
};

static bool
cmdDomainSnapshotRevert(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;
    bool force = false;
    int result;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED;
    /* We want virsh snapshot-revert --force to work even when talking
     * to older servers that did the unsafe revert by default but
     * reject the flag, so we probe without the flag, and only use it
     * when the error says it will make a difference.  */
    if (vshCommandOptBool(cmd, "force"))
        force = true;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        goto cleanup;

    result = virDomainRevertToSnapshot(snapshot, flags);
    if (result < 0 && force &&
        last_error->code == VIR_ERR_SNAPSHOT_REVERT_RISKY) {
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_FORCE;
        vshResetLibvirtError();
        result = virDomainRevertToSnapshot(snapshot, flags);
    }
    if (result < 0)
        goto cleanup;

    ret = true;

 cleanup:
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-delete" command
 */
static const vshCmdInfo info_snapshot_delete[] = {
    {.name = "help",
     .data = N_("Delete a domain snapshot")
    },
    {.name = "desc",
     .data = N_("Snapshot Delete")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_snapshot_delete[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("delete current snapshot")),
    {.name = "children",
     .type = VSH_OT_BOOL,
     .help = N_("delete snapshot and all children")
    },
    {.name = "children-only",
     .type = VSH_OT_BOOL,
     .help = N_("delete children but not snapshot")
    },
    {.name = "metadata",
     .type = VSH_OT_BOOL,
     .help = N_("delete only libvirt metadata, leaving snapshot contents behind")
    },
    {.name = NULL}
};

static bool
cmdSnapshotDelete(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN;
    if (vshCommandOptBool(cmd, "children-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY;
    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;

    /* XXX If we wanted, we could emulate DELETE_CHILDREN_ONLY even on
     * older servers that reject the flag, by manually computing the
     * list of descendants.  But that's a lot of code to maintain.  */
    if (virDomainSnapshotDelete(snapshot, flags) == 0) {
        if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)
            vshPrintExtra(ctl, _("Domain snapshot %s children deleted\n"), name);
        else
            vshPrintExtra(ctl, _("Domain snapshot %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete snapshot %s"), name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

const vshCmdDef snapshotCmds[] = {
    {.name = "snapshot-create",
     .handler = cmdSnapshotCreate,
     .opts = opts_snapshot_create,
     .info = info_snapshot_create,
     .flags = 0
    },
    {.name = "snapshot-create-as",
     .handler = cmdSnapshotCreateAs,
     .opts = opts_snapshot_create_as,
     .info = info_snapshot_create_as,
     .flags = 0
    },
    {.name = "snapshot-current",
     .handler = cmdSnapshotCurrent,
     .opts = opts_snapshot_current,
     .info = info_snapshot_current,
     .flags = 0
    },
    {.name = "snapshot-delete",
     .handler = cmdSnapshotDelete,
     .opts = opts_snapshot_delete,
     .info = info_snapshot_delete,
     .flags = 0
    },
    {.name = "snapshot-dumpxml",
     .handler = cmdSnapshotDumpXML,
     .opts = opts_snapshot_dumpxml,
     .info = info_snapshot_dumpxml,
     .flags = 0
    },
    {.name = "snapshot-edit",
     .handler = cmdSnapshotEdit,
     .opts = opts_snapshot_edit,
     .info = info_snapshot_edit,
     .flags = 0
    },
    {.name = "snapshot-info",
     .handler = cmdSnapshotInfo,
     .opts = opts_snapshot_info,
     .info = info_snapshot_info,
     .flags = 0
    },
    {.name = "snapshot-list",
     .handler = cmdSnapshotList,
     .opts = opts_snapshot_list,
     .info = info_snapshot_list,
     .flags = 0
    },
    {.name = "snapshot-parent",
     .handler = cmdSnapshotParent,
     .opts = opts_snapshot_parent,
     .info = info_snapshot_parent,
     .flags = 0
    },
    {.name = "snapshot-revert",
     .handler = cmdDomainSnapshotRevert,
     .opts = opts_snapshot_revert,
     .info = info_snapshot_revert,
     .flags = 0
    },
    {.name = NULL}
};
