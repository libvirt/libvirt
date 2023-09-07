/*
 * virsh-snapshot.c: Commands to manage domain snapshot
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
#include "virsh-snapshot.h"

#include <assert.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virsh-util.h"
#include "virxml.h"
#include "conf/virdomainsnapshotobjlist.h"
#include "vsh-table.h"

/* Helper for snapshot-create and snapshot-create-as */
static bool
virshSnapshotCreate(vshControl *ctl, virDomainPtr dom, const char *buffer,
                    unsigned int flags, const char *from)
{
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    bool halt = false;
    const char *name = NULL;

    snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);

    /* If no source file but validate was not recognized, try again without
     * that flag. */
    if (!snapshot && last_error->code == VIR_ERR_NO_SUPPORT && !from) {
        flags &= ~VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE;
        snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);
    }

    /* Emulate --halt on older servers.  */
    if (!snapshot && last_error->code == VIR_ERR_INVALID_ARG &&
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        int persistent;

        vshResetLibvirtError();
        persistent = virDomainIsPersistent(dom);
        if (persistent < 0) {
            vshReportError(ctl);
            return false;
        }
        if (!persistent) {
            vshError(ctl, "%s",
                     _("cannot halt after snapshot of transient domain"));
            return false;
        }
        if (virDomainIsActive(dom) == 1)
            halt = true;
        flags &= ~VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
        snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);
    }

    if (snapshot == NULL)
        return false;

    if (halt && virDomainDestroy(dom) < 0) {
        vshReportError(ctl);
        return false;
    }

    name = virDomainSnapshotGetName(snapshot);
    if (!name) {
        vshError(ctl, "%s", _("Could not get snapshot name"));
        return false;
    }

    if (from)
        vshPrintExtra(ctl, _("Domain snapshot %1$s created from '%2$s'"), name, from);
    else
        vshPrintExtra(ctl, _("Domain snapshot %1$s created"), name);

    return true;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "xmlfile",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
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
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema"),
    },
    {.name = NULL}
};

static bool
cmdSnapshotCreate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
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
    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "xmlfile", &from) < 0)
        return false;
    if (!from) {
        buffer = g_strdup("<domainsnapshot/>");
    } else {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            vshSaveLibvirtError();
            return false;
        }
    }

    return virshSnapshotCreate(ctl, dom, buffer, flags, from);
}

/*
 * "snapshot-create-as" command
 */
static int
virshParseSnapshotMemspec(vshControl *ctl, virBuffer *buf, const char *str)
{
    int ret = -1;
    const char *snapshot = NULL;
    const char *file = NULL;
    g_auto(GStrv) array = NULL;
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
        vshError(ctl, _("unable to parse memspec: %1$s"), str);
    return ret;
}

static int
virshParseSnapshotDiskspec(vshControl *ctl, virBuffer *buf, const char *str)
{
    int ret = -1;
    const char *name = NULL;
    const char *snapshot = NULL;
    const char *driver = NULL;
    const char *stype = NULL;
    const char *file = NULL;
    g_auto(GStrv) array = NULL;
    int narray;
    size_t i;
    bool isFile = true;

    narray = vshStringToArray(str, &array);
    if (narray <= 0)
        goto cleanup;

    name = array[0];
    for (i = 1; i < narray; i++) {
        if (!snapshot && STRPREFIX(array[i], "snapshot="))
            snapshot = array[i] + strlen("snapshot=");
        else if (!driver && STRPREFIX(array[i], "driver="))
            driver = array[i] + strlen("driver=");
        else if (!stype && STRPREFIX(array[i], "stype="))
            stype = array[i] + strlen("stype=");
        else if (!file && STRPREFIX(array[i], "file="))
            file = array[i] + strlen("file=");
        else
            goto cleanup;
    }

    virBufferEscapeString(buf, "<disk name='%s'", name);
    if (snapshot)
        virBufferAsprintf(buf, " snapshot='%s'", snapshot);
    if (stype) {
        if (STREQ(stype, "block")) {
            isFile = false;
        } else if (STRNEQ(stype, "file")) {
            vshError(ctl, _("Unknown storage type: '%1$s'"), stype);
            goto cleanup;
        }
        virBufferAsprintf(buf, " type='%s'", stype);
    }
    if (driver || file) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        if (driver)
            virBufferAsprintf(buf, "<driver type='%s'/>\n", driver);
        if (file) {
            if (isFile)
                virBufferEscapeString(buf, "<source file='%s'/>\n", file);
            else
                virBufferEscapeString(buf, "<source dev='%s'/>\n", file);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</disk>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    ret = 0;
 cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse diskspec: %1$s"), str);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "name",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("name of snapshot")
    },
    {.name = "description",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
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
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema"),
    },
    {.name = "memspec",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("memory attributes: [file=]name[,snapshot=type]")
    },
    {.name = "diskspec",
     .type = VSH_OT_ARGV,
     .help = N_("disk attributes: disk[,snapshot=type][,driver=type][,stype=type][,file=name]")
    },
    {.name = NULL}
};

static bool
cmdSnapshotCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    const char *memspec = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;

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
    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "description", &desc) < 0)
        return false;

    virBufferAddLit(&buf, "<domainsnapshot>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", name);
    virBufferEscapeString(&buf, "<description>%s</description>\n", desc);

    if (vshCommandOptStringReq(ctl, cmd, "memspec", &memspec) < 0)
        return false;

    if (memspec && virshParseSnapshotMemspec(ctl, &buf, memspec) < 0)
        return false;

    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "<disks>\n");
        virBufferAdjustIndent(&buf, 2);
        while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
            if (virshParseSnapshotDiskspec(ctl, &buf, opt->data) < 0)
                return false;
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</disks>\n");
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domainsnapshot>\n");

    buffer = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s\n",  buffer);
        return true;
    }

    return virshSnapshotCreate(ctl, dom, buffer, flags, NULL);
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
        vshError(ctl, _("--%1$s and --current are mutually exclusive"), arg);
        return -1;
    }

    if (snapname) {
        *snap = virDomainSnapshotLookupByName(dom, snapname, 0);
    } else if (current) {
        *snap = virDomainSnapshotCurrent(dom, 0);
    } else {
        vshError(ctl, _("--%1$s or --current is required"), arg);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name"),
     .completer = virshSnapshotNameCompleter,
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
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    g_autoptr(virshDomainSnapshot) edited = NULL;
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
#define EDIT_NOT_CHANGED \
    do { \
        /* Depending on flags, we re-edit even if XML is unchanged.  */ \
        if (!(define_flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) { \
            vshPrintExtra(ctl, \
                          _("Snapshot %1$s XML configuration not changed.\n"), \
                          name); \
            ret = true; \
            goto edit_cleanup; \
        } \
    } while (0)
#define EDIT_DEFINE \
    (strstr(doc, "<state>disk-snapshot</state>") ? \
    define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY : 0), \
    edited = virDomainSnapshotCreateXML(dom, doc_edited, define_flags)
#include "virsh-edit.c"

    edited_name = virDomainSnapshotGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrintExtra(ctl, _("Snapshot %1$s edited.\n"), name);
    } else if (clone_okay) {
        vshPrintExtra(ctl, _("Snapshot %1$s cloned to %2$s.\n"), name,
                      edited_name);
    } else {
        unsigned int delete_flags;

        delete_flags = VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;
        if (virDomainSnapshotDelete(rename_okay ? snapshot : edited,
                                    delete_flags) < 0) {
            vshReportError(ctl);
            vshError(ctl, _("Failed to clean up %1$s"),
                     rename_okay ? name : edited_name);
            goto cleanup;
        }
        if (!rename_okay) {
            vshError(ctl, _("Must use --rename or --clone to change %1$s to %2$s"),
                     name, edited_name);
            goto cleanup;
        }
    }

    ret = true;

 cleanup:
    if (!ret && name)
        vshError(ctl, _("Failed to update %1$s"), name);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
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
     .help = N_("name of existing snapshot to make current"),
     .completer = virshSnapshotNameCompleter,
    },
    {.name = NULL}
};

static bool
cmdSnapshotCurrent(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    int current;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    g_autofree char *xml = NULL;
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
        g_autoptr(virshDomainSnapshot) snapshot2 = NULL;
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

        vshPrintExtra(ctl, _("Snapshot %1$s set as current"), snapshotname);
        ret = true;
        goto cleanup;
    }

    if ((current = virDomainHasCurrentSnapshot(dom, 0)) < 0)
        goto cleanup;

    if (!current) {
        vshError(ctl, _("domain '%1$s' has no current snapshot"), domname);
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
    g_autoptr(virshDomainSnapshot) parent = NULL;
    g_autofree char *xml = NULL;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int ret = -1;
    virshControl *priv = ctl->privData;

    *parent_name = NULL;

    /* Try new API, since it is faster. */
    if (!priv->useSnapshotOld) {
        parent = virDomainSnapshotGetParent(snapshot, 0);
        if (parent) {
            /* API works, and virDomainSnapshotGetName will succeed */
            *parent_name = g_strdup(virDomainSnapshotGetName(parent));
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
    g_autofree char *xml = NULL;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *state = NULL;

    if (!snapshot)
        return 1;

    xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!xml)
        return -1;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        return -1;

    /* Libvirt 1.0.1 and newer never call this function, because the
     * filtering is already supported by the listing functions.  Older
     * libvirt lacked /domainsnapshot/memory, but was also limited in
     * the types of snapshots it could create: if state was disk-only,
     * the snapshot is external; all other snapshots are internal.  */
    state = virXPathString("string(/domainsnapshot/state)", ctxt);
    if (!state) {
        vshError(ctl, "%s", _("unable to perform snapshot filtering"));
        return -1;
    }
    if (STREQ(state, "disk-snapshot")) {
        return !!((flags & VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY) &&
                  (flags & VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL));
    }

    if (!(flags & VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL))
        return 0;
    if (STREQ(state, "shutoff"))
        return !!(flags & VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE);
    return !!(flags & VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name"),
     .completer = virshSnapshotNameCompleter,
    },
    VIRSH_COMMON_OPT_CURRENT(N_("info on current snapshot")),
    {.name = NULL}
};

static bool
cmdSnapshotInfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    const char *name;
    g_autofree char *doc = NULL;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *state = NULL;
    int external;
    g_autofree char *parent = NULL;
    int count;
    unsigned int flags;
    int current;
    int metadata;
    virshControl *priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), name);
    vshPrint(ctl, "%-15s %s\n", _("Domain:"), virDomainGetName(dom));

    /* Determine if snapshot is current; this is useful enough that we
     * attempt a fallback.  */
    current = virDomainSnapshotIsCurrent(snapshot, 0);
    if (current < 0) {
        vshResetLibvirtError();
        current = 0;
    }
    vshPrint(ctl, "%-15s %s\n", _("Current:"),
             current > 0 ? _("yes") : _("no"));

    /* Get the XML configuration of the snapshot to determine the
     * state of the machine at the time of the snapshot.  */
    doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!doc)
        return false;

    xmldoc = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        return false;

    state = virXPathString("string(/domainsnapshot/state)", ctxt);
    if (!state) {
        vshError(ctl, "%s",
                 _("unexpected problem reading snapshot xml"));
        return false;
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
        return false;
    }
    vshPrint(ctl, "%-15s %s\n", _("Location:"),
             external ? _("external") : _("internal"));

    /* Since we already have the XML, there's no need to call
     * virDomainSnapshotGetParent */
    parent = virXPathString("string(/domainsnapshot/parent/name)", ctxt);
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), NULLSTR_MINUS(parent));

    /* Children, Descendants.  After this point, the fallback to
     * compute children is too expensive, so we gracefully quit if the
     * APIs don't exist.  */
    if (priv->useSnapshotOld)
        return true;
    flags = 0;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT) {
            vshResetLibvirtError();
            return true;
        }
        return false;
    }
    vshPrint(ctl, "%-15s %d\n", _("Children:"), count);
    flags = VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0)
        return false;
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

    return true;
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

static void
virshSnapshotListFree(struct virshSnapshotList *snaplist)
{
    size_t i;

    if (!snaplist)
        return;
    if (snaplist->snaps) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            virshDomainSnapshotFree(snaplist->snaps[i].snap);
            g_free(snaplist->snaps[i].parent);
        }
        g_free(snaplist->snaps);
    }
    g_free(snaplist);
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
static struct virshSnapshotList *
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
    struct virshSnapshotList *snaplist = g_new0(struct virshSnapshotList, 1);
    struct virshSnapshotList *ret = NULL;
    const char *fromname = NULL;
    int start_index = -1;
    int deleted = 0;
    bool filter_fallback = false;
    unsigned int flags = orig_flags;
    virshControl *priv = ctl->privData;

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
        if (tree && from)
            snaplist->snaps = g_new0(struct virshSnap, count + 1);
        else
            snaplist->snaps = g_new0(struct virshSnap, count);
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

    names = g_new0(char *, count);

    /* Now that we have a count, collect the list.  */
    if (from && !priv->useSnapshotOld) {
        if (tree) {
            count = virDomainSnapshotListChildrenNames(from, names + 1,
                                                       count - 1, flags);
            if (count >= 0) {
                count++;
                names[0] = g_strdup(fromname);
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

    snaplist->snaps = g_new0(struct virshSnap, count);
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
                g_clear_pointer(&snaplist->snaps[i].snap,
                                virshDomainSnapshotFree);
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
            vshError(ctl, _("snapshot %1$s disappeared from list"), fromname);
            goto cleanup;
        }
        for (i = 0; i < count; i++) {
            if (i == start_index || !snaplist->snaps[i].parent) {
                VIR_FREE(names[i]);
                g_clear_pointer(&snaplist->snaps[i].snap,
                                virshDomainSnapshotFree);
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
            ret = g_new0(struct virshSnapshotList, 1);
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
                    g_clear_pointer(&snaplist->snaps[i].snap,
                                    virshDomainSnapshotFree);
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
        orig_flags |= VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS;
        orig_flags |= VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION;

        for (i = 0; i < snaplist->nsnaps; i++) {
            switch (virshSnapshotFilter(ctl, snaplist->snaps[i].snap,
                                        orig_flags)) {
            case 1:
                break;
            case 0:
                g_clear_pointer(&snaplist->snaps[i].snap,
                                virshDomainSnapshotFree);
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
                break;
            default:
                goto cleanup;
            }
        }
    }
    if (!(orig_flags & VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL) &&
        snaplist->snaps && snaplist->nsnaps) {
        qsort(snaplist->snaps, snaplist->nsnaps, sizeof(*snaplist->snaps),
              virshSnapSorter);
    }
    snaplist->nsnaps -= deleted;

    ret = g_steal_pointer(&snaplist);

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
    struct virshSnapshotList *snaplist = opaque;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
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
     .help = N_("filter by snapshots taken while active (full system snapshots)")
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
     .completer = virshSnapshotNameCompleter,
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
    {.name = "topological",
     .type = VSH_OT_BOOL,
     .help = N_("sort list topologically rather than by name"),
    },

    {.name = NULL}
};

static bool
cmdSnapshotList(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    size_t i;
    virDomainSnapshotPtr snapshot = NULL;
    long long creation_longlong;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool name = vshCommandOptBool(cmd, "name");
    bool from = vshCommandOptBool(cmd, "from");
    bool parent = vshCommandOptBool(cmd, "parent");
    bool roots = vshCommandOptBool(cmd, "roots");
    bool current = vshCommandOptBool(cmd, "current");
    const char *from_snap = NULL;
    g_autoptr(virshDomainSnapshot) start = NULL;
    struct virshSnapshotList *snaplist = NULL;
    g_autoptr(vshTable) table = NULL;

    VSH_EXCLUSIVE_OPTIONS_VAR(tree, name);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, roots);
    VSH_EXCLUSIVE_OPTIONS_VAR(parent, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, tree);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, from);
    VSH_EXCLUSIVE_OPTIONS_VAR(roots, current);

#define FILTER(option, flag) \
    do { \
        if (vshCommandOptBool(cmd, option)) { \
            if (tree) { \
                vshError(ctl, \
                         _("--%1$s and --tree are mutually exclusive"), \
                         option); \
                return false; \
            } \
            flags |= VIR_DOMAIN_SNAPSHOT_LIST_ ## flag; \
        } \
    } while (0)

    FILTER("leaves", LEAVES);
    FILTER("no-leaves", NO_LEAVES);
    FILTER("inactive", INACTIVE);
    FILTER("active", ACTIVE);
    FILTER("disk-only", DISK_ONLY);
    FILTER("internal", INTERNAL);
    FILTER("external", EXTERNAL);
#undef FILTER

    if (vshCommandOptBool(cmd, "topological"))
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL;

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
            table = vshTableNew(_("Name"), _("Creation Time"), _("State"), _("Parent"), NULL);
        else
            table = vshTableNew(_("Name"), _("Creation Time"), _("State"), NULL);

        if (!table)
            goto cleanup;
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
        g_autoptr(GDateTime) then = NULL;
        g_autofree gchar *thenstr = NULL;
        g_autoptr(xmlDoc) xml = NULL;
        g_autoptr(xmlXPathContext) ctxt = NULL;
        g_autofree char *parent_snap = NULL;
        g_autofree char *state = NULL;
        g_autofree char *doc = NULL;
        const char *snap_name;

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
        then = g_date_time_new_from_unix_local(creation_longlong);
        thenstr = g_date_time_format(then, "%Y-%m-%d %H:%M:%S %z");

        if (parent) {
            if (vshTableRowAppend(table, snap_name, thenstr, state,
                                  NULLSTR_EMPTY(parent_snap),
                                  NULL) < 0)
                goto cleanup;
        } else {
            if (vshTableRowAppend(table, snap_name, thenstr, state,
                                  NULL) < 0)
                goto cleanup;
        }
    }

    if (table)
        vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    virshSnapshotListFree(snaplist);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("snapshot name"),
     .completer = virshSnapshotNameCompleter,
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
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
cmdSnapshotDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "snapshotname", &name) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (!(snapshot = virDomainSnapshotLookupByName(dom, name, 0)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virDomainSnapshotGetXMLDesc(snapshot, flags)))
        return false;

    return virshDumpXML(ctl, xml, "domain-snapshot", xpath, wrap);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("find parent of snapshot name"),
     .completer = virshSnapshotNameCompleter,
    },
    VIRSH_COMMON_OPT_CURRENT(N_("find parent of current snapshot")),
    {.name = NULL}
};

static bool
cmdSnapshotParent(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    g_autofree char *parent = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        return false;

    if (virshGetSnapshotParent(ctl, snapshot, &parent) < 0)
        return false;
    if (!parent) {
        vshError(ctl, _("snapshot '%1$s' has no parent"), name);
        return false;
    }

    vshPrint(ctl, "%s", parent);

    return true;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name"),
     .completer = virshSnapshotNameCompleter,
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
    {.name = "reset-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("re-initialize NVRAM from its pristine template")
    },
    {.name = NULL}
};

static bool
cmdDomainSnapshotRevert(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    unsigned int flags = 0;
    bool force = false;
    int result;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED;
    if (vshCommandOptBool(cmd, "reset-nvram"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_RESET_NVRAM;
    /* We want virsh snapshot-revert --force to work even when talking
     * to older servers that did the unsafe revert by default but
     * reject the flag, so we probe without the flag, and only use it
     * when the error says it will make a difference.  */
    if (vshCommandOptBool(cmd, "force"))
        force = true;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        return false;

    result = virDomainRevertToSnapshot(snapshot, flags);
    if (result < 0 && force &&
        last_error->code == VIR_ERR_SNAPSHOT_REVERT_RISKY) {
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_FORCE;
        vshResetLibvirtError();
        result = virDomainRevertToSnapshot(snapshot, flags);
    }

    if (result < 0)
        vshError(ctl, _("Failed to revert snapshot %1$s"), name);
    else
        vshPrintExtra(ctl, _("Domain snapshot %1$s reverted\n"), name);
    return result >= 0;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT),
    {.name = "snapshotname",
     .type = VSH_OT_STRING,
     .help = N_("snapshot name"),
     .completer = virshSnapshotNameCompleter,
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
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    g_autoptr(virshDomainSnapshot) snapshot = NULL;
    unsigned int flags = 0;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (virshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                            &snapshot, &name) < 0)
        return false;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN;
    if (vshCommandOptBool(cmd, "children-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY;
    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;

    /* XXX If we wanted, we could emulate DELETE_CHILDREN_ONLY even on
     * older servers that reject the flag, by manually computing the
     * list of descendants.  But that's a lot of code to maintain.  */
    if (virDomainSnapshotDelete(snapshot, flags) < 0) {
        vshError(ctl, _("Failed to delete snapshot %1$s"), name);
        return false;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)
        vshPrintExtra(ctl, _("Domain snapshot %1$s children deleted\n"), name);
    else
        vshPrintExtra(ctl, _("Domain snapshot %1$s deleted\n"), name);
    return true;
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
