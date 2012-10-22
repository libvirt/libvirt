/*
 * virsh-snapshot.c: Commands to manage domain snapshot
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
#include "buf.h"
#include "memory.h"
#include "util.h"
#include "virsh-domain.h"
#include "xml.h"

/* Helper for snapshot-create and snapshot-create-as */
static bool
vshSnapshotCreate(vshControl *ctl, virDomainPtr dom, const char *buffer,
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
        vshPrint(ctl, _("Domain snapshot %s created from '%s'"), name, from);
    else
        vshPrint(ctl, _("Domain snapshot %s created"), name);

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
    {"help", N_("Create a snapshot from XML")},
    {"desc", N_("Create a snapshot (disk and RAM) from XML")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_create[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"xmlfile", VSH_OT_DATA, 0, N_("domain snapshot XML")},
    {"redefine", VSH_OT_BOOL, 0, N_("redefine metadata for existing snapshot")},
    {"current", VSH_OT_BOOL, 0, N_("with redefine, set current snapshot")},
    {"no-metadata", VSH_OT_BOOL, 0, N_("take snapshot but create no metadata")},
    {"halt", VSH_OT_BOOL, 0, N_("halt domain after snapshot is created")},
    {"disk-only", VSH_OT_BOOL, 0, N_("capture disk state but not vm state")},
    {"reuse-external", VSH_OT_BOOL, 0, N_("reuse any existing external files")},
    {"quiesce", VSH_OT_BOOL, 0, N_("quiesce guest's file systems")},
    {"atomic", VSH_OT_BOOL, 0, N_("require atomic operation")},
    {NULL, 0, 0, NULL}
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

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "xmlfile", &from) <= 0)
        buffer = vshStrdup(ctl, "<domainsnapshot/>");
    else {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            /* we have to report the error here because during cleanup
             * we'll run through virDomainFree(), which loses the
             * last error
             */
            vshReportError(ctl);
            goto cleanup;
        }
    }
    if (buffer == NULL) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    ret = vshSnapshotCreate(ctl, dom, buffer, flags, from);

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
vshParseSnapshotDiskspec(vshControl *ctl, virBufferPtr buf, const char *str)
{
    int ret = -1;
    char *name = NULL;
    char *snapshot = NULL;
    char *driver = NULL;
    char *file = NULL;
    char *spec = vshStrdup(ctl, str);
    char *tmp = spec;
    size_t len = strlen(str);

    if (*str == ',')
        goto cleanup;
    name = tmp;
    while ((tmp = strchr(tmp, ','))) {
        if (tmp[1] == ',') {
            /* Recognize ,, as an escape for a literal comma */
            memmove(&tmp[1], &tmp[2], len - (tmp - spec) - 2 + 1);
            len--;
            tmp++;
            continue;
        }
        /* Terminate previous string, look for next recognized one */
        *tmp++ = '\0';
        if (!snapshot && STRPREFIX(tmp, "snapshot="))
            snapshot = tmp + strlen("snapshot=");
        else if (!driver && STRPREFIX(tmp, "driver="))
            driver = tmp + strlen("driver=");
        else if (!file && STRPREFIX(tmp, "file="))
            file = tmp + strlen("file=");
        else
            goto cleanup;
    }

    virBufferEscapeString(buf, "    <disk name='%s'", name);
    if (snapshot)
        virBufferAsprintf(buf, " snapshot='%s'", snapshot);
    if (driver || file) {
        virBufferAddLit(buf, ">\n");
        if (driver)
            virBufferAsprintf(buf, "      <driver type='%s'/>\n", driver);
        if (file)
            virBufferEscapeString(buf, "      <source file='%s'/>\n", file);
        virBufferAddLit(buf, "    </disk>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    ret = 0;
cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse diskspec: %s"), str);
    VIR_FREE(spec);
    return ret;
}

static const vshCmdInfo info_snapshot_create_as[] = {
    {"help", N_("Create a snapshot from a set of args")},
    {"desc", N_("Create a snapshot (disk and RAM) from arguments")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_create_as[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"name", VSH_OT_DATA, 0, N_("name of snapshot")},
    {"description", VSH_OT_DATA, 0, N_("description of snapshot")},
    {"print-xml", VSH_OT_BOOL, 0, N_("print XML document rather than create")},
    {"no-metadata", VSH_OT_BOOL, 0, N_("take snapshot but create no metadata")},
    {"halt", VSH_OT_BOOL, 0, N_("halt domain after snapshot is created")},
    {"disk-only", VSH_OT_BOOL, 0, N_("capture disk state but not vm state")},
    {"reuse-external", VSH_OT_BOOL, 0, N_("reuse any existing external files")},
    {"quiesce", VSH_OT_BOOL, 0, N_("quiesce guest's file systems")},
    {"atomic", VSH_OT_BOOL, 0, N_("require atomic operation")},
    {"diskspec", VSH_OT_ARGV, 0,
     N_("disk attributes: disk[,snapshot=type][,driver=type][,file=name]")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
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

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "name", &name) < 0 ||
        vshCommandOptString(cmd, "description", &desc) < 0) {
        vshError(ctl, _("argument must not be empty"));
        goto cleanup;
    }

    virBufferAddLit(&buf, "<domainsnapshot>\n");
    if (name)
        virBufferEscapeString(&buf, "  <name>%s</name>\n", name);
    if (desc)
        virBufferEscapeString(&buf, "  <description>%s</description>\n", desc);
    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "  <disks>\n");
        while ((opt = vshCommandOptArgv(cmd, opt))) {
            if (vshParseSnapshotDiskspec(ctl, &buf, opt->data) < 0) {
                virBufferFreeAndReset(&buf);
                goto cleanup;
            }
        }
        virBufferAddLit(&buf, "  </disks>\n");
    }
    virBufferAddLit(&buf, "</domainsnapshot>\n");

    buffer = virBufferContentAndReset(&buf);
    if (buffer == NULL) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s\n",  buffer);
        ret = true;
        goto cleanup;
    }

    ret = vshSnapshotCreate(ctl, dom, buffer, flags, NULL);

cleanup:
    VIR_FREE(buffer);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/* Helper for resolving {--current | --ARG name} into a snapshot
 * belonging to DOM.  If EXCLUSIVE, fail if both --current and arg are
 * present.  On success, populate *SNAP and *NAME, before returning 0.
 * On failure, return -1 after issuing an error message.  */
static int
vshLookupSnapshot(vshControl *ctl, const vshCmd *cmd,
                  const char *arg, bool exclusive, virDomainPtr dom,
                  virDomainSnapshotPtr *snap, const char **name)
{
    bool current = vshCommandOptBool(cmd, "current");
    const char *snapname = NULL;

    if (vshCommandOptString(cmd, arg, &snapname) < 0) {
        vshError(ctl, _("invalid argument for --%s"), arg);
        return -1;
    }

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
    {"help", N_("edit XML for a snapshot")},
    {"desc", N_("Edit the domain snapshot XML for a named snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_edit[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("also set edited snapshot as current")},
    {"rename", VSH_OT_BOOL, 0, N_("allow renaming an existing snapshot")},
    {"clone", VSH_OT_BOOL, 0, N_("allow cloning to new name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotEdit(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virDomainSnapshotPtr edited = NULL;
    const char *name;
    const char *edited_name;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    bool rename_okay = vshCommandOptBool(cmd, "rename");
    bool clone_okay = vshCommandOptBool(cmd, "clone");

    if (rename_okay && clone_okay) {
        vshError(ctl, "%s",
                 _("--rename and --clone are mutually exclusive"));
        return false;
    }

    if (vshCommandOptBool(cmd, "current") &&
        vshCommandOptBool(cmd, "snapshotname"))
        define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", false, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

#define EDIT_GET_XML \
    virDomainSnapshotGetXMLDesc(snapshot, getxml_flags)
#define EDIT_NOT_CHANGED \
    /* Depending on flags, we re-edit even if XML is unchanged.  */ \
    if (!(define_flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) {     \
        vshPrint(ctl,                                               \
                 _("Snapshot %s XML configuration not changed.\n"), \
                 name);                                             \
        ret = true;                                                 \
        goto edit_cleanup;                                          \
    }
#define EDIT_DEFINE \
    (strstr(doc, "<state>disk-snapshot</state>") ? \
    define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY : 0), \
    edited = virDomainSnapshotCreateXML(dom, doc_edited, define_flags)
#define EDIT_FREE \
    if (edited) \
        virDomainSnapshotFree(edited);
#include "virsh-edit.c"

    edited_name = virDomainSnapshotGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrint(ctl, _("Snapshot %s edited.\n"), name);
    } else if (clone_okay) {
        vshPrint(ctl, _("Snapshot %s cloned to %s.\n"), name,
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
    if (!ret)
        vshError(ctl, _("Failed to update %s"), name);
    if (edited)
        virDomainSnapshotFree(edited);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "snapshot-current" command
 */
static const vshCmdInfo info_snapshot_current[] = {
    {"help", N_("Get or set the current snapshot")},
    {"desc", N_("Get or set the current snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_current[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"name", VSH_OT_BOOL, 0, N_("list the name, rather than the full xml")},
    {"security-info", VSH_OT_BOOL, 0,
     N_("include security sensitive information in XML dump")},
    {"snapshotname", VSH_OT_DATA, 0,
     N_("name of existing snapshot to make current")},
    {NULL, 0, 0, NULL}
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

    dom = vshCommandOptDomain(ctl, cmd, &domname);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "snapshotname", &snapshotname) < 0) {
        vshError(ctl, _("invalid snapshotname argument '%s'"), snapshotname);
        goto cleanup;
    }
    if (snapshotname) {
        virDomainSnapshotPtr snapshot2 = NULL;
        flags = (VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                 VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT);

        if (vshCommandOptBool(cmd, "name")) {
            vshError(ctl, "%s",
                     _("--name and snapshotname are mutually exclusive"));
            goto cleanup;
        }
        snapshot = virDomainSnapshotLookupByName(dom, snapshotname, 0);
        if (snapshot == NULL)
            goto cleanup;
        xml = virDomainSnapshotGetXMLDesc(snapshot, VIR_DOMAIN_XML_SECURE);
        if (!xml)
            goto cleanup;
        /* strstr is safe here, since xml came from libvirt API and not user */
        if (strstr(xml, "<state>disk-snapshot</state>"))
            flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
        snapshot2 = virDomainSnapshotCreateXML(dom, xml, flags);
        if (snapshot2 == NULL)
            goto cleanup;
        virDomainSnapshotFree(snapshot2);
        vshPrint(ctl, _("Snapshot %s set as current"), snapshotname);
        ret = true;
        goto cleanup;
    }

    current = virDomainHasCurrentSnapshot(dom, 0);
    if (current < 0) {
        goto cleanup;
    } else if (!current) {
        vshError(ctl, _("domain '%s' has no current snapshot"), domname);
        goto cleanup;
    } else {
        const char *name = NULL;

        if (!(snapshot = virDomainSnapshotCurrent(dom, 0)))
            goto cleanup;

        if (vshCommandOptBool(cmd, "name")) {
            name = virDomainSnapshotGetName(snapshot);
            if (!name)
                goto cleanup;
        } else {
            xml = virDomainSnapshotGetXMLDesc(snapshot, flags);
            if (!xml)
                goto cleanup;
        }

        vshPrint(ctl, "%s", name ? name : xml);
    }

    ret = true;

cleanup:
    if (!ret)
        vshReportError(ctl);
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/* Helper function to get the name of a snapshot's parent.  Caller
 * must free the result.  Returns 0 on success (including when it was
 * proven no parent exists), and -1 on failure with error reported
 * (such as no snapshot support or domain deleted in meantime).  */
static int
vshGetSnapshotParent(vshControl *ctl, virDomainSnapshotPtr snapshot,
                     char **parent_name)
{
    virDomainSnapshotPtr parent = NULL;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    *parent_name = NULL;

    /* Try new API, since it is faster. */
    if (!ctl->useSnapshotOld) {
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
        ctl->useSnapshotOld = true;
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

/*
 * "snapshot-info" command
 */
static const vshCmdInfo info_snapshot_info[] = {
    {"help", N_("snapshot information")},
    {"desc", N_("Returns basic information about a snapshot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_info[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("info on current snapshot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotInfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainSnapshotPtr snapshot = NULL;
    const char *name;
    char *doc = NULL;
    char *tmp;
    char *parent = NULL;
    bool ret = false;
    int count;
    unsigned int flags;
    int current;
    int metadata;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
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

    tmp = strstr(doc, "<state>");
    if (!tmp) {
        vshError(ctl, "%s",
                 _("unexpected problem reading snapshot xml"));
        goto cleanup;
    }
    tmp += strlen("<state>");
    vshPrint(ctl, "%-15s %.*s\n", _("State:"),
             (int) (strchr(tmp, '<') - tmp), tmp);

    if (vshGetSnapshotParent(ctl, snapshot, &parent) < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), parent ? parent : "-");

    /* Children, Descendants.  After this point, the fallback to
     * compute children is too expensive, so we gracefully quit if the
     * APIs don't exist.  */
    if (ctl->useSnapshotOld) {
        ret = true;
        goto cleanup;
    }
    flags = 0;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0)
        goto cleanup;
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
    VIR_FREE(doc);
    VIR_FREE(parent);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);
    return ret;
}

/* Helpers for collecting a list of snapshots.  */
struct vshSnap {
    virDomainSnapshotPtr snap;
    char *parent;
};
struct vshSnapshotList {
    struct vshSnap *snaps;
    int nsnaps;
};
typedef struct vshSnapshotList *vshSnapshotListPtr;

static void
vshSnapshotListFree(vshSnapshotListPtr snaplist)
{
    int i;

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
vshSnapSorter(const void *a, const void *b)
{
    const struct vshSnap *sa = a;
    const struct vshSnap *sb = b;

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
static vshSnapshotListPtr
vshSnapshotListCollect(vshControl *ctl, virDomainPtr dom,
                       virDomainSnapshotPtr from,
                       unsigned int flags, bool tree)
{
    int i;
    char **names = NULL;
    int count = -1;
    bool descendants = false;
    bool roots = false;
    virDomainSnapshotPtr *snaps;
    vshSnapshotListPtr snaplist = vshMalloc(ctl, sizeof(*snaplist));
    vshSnapshotListPtr ret = NULL;
    const char *fromname = NULL;
    int start_index = -1;
    int deleted = 0;

    /* Try the interface available in 0.9.13 and newer.  */
    if (!ctl->useSnapshotOld) {
        if (from)
            count = virDomainSnapshotListAllChildren(from, &snaps, flags);
        else
            count = virDomainListAllSnapshots(dom, &snaps, flags);
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
                if (vshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
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
        if (ctl->useSnapshotOld ||
            ((count = virDomainSnapshotNumChildren(from, flags)) < 0 &&
             last_error->code == VIR_ERR_NO_SUPPORT)) {
            /* We can emulate --from.  */
            /* XXX can we also emulate --leaves? */
            vshResetLibvirtError();
            ctl->useSnapshotOld = true;
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
    if (from && !ctl->useSnapshotOld) {
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
    if (tree || (from && ctl->useSnapshotOld) || roots) {
        for (i = (from && !ctl->useSnapshotOld); i < count; i++) {
            if (from && ctl->useSnapshotOld && STREQ(names[i], fromname)) {
                start_index = i;
                if (tree)
                    continue;
            }
            if (vshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
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

    if (ctl->useSnapshotOld && descendants) {
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
                int j;

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
    qsort(snaplist->snaps, snaplist->nsnaps, sizeof(*snaplist->snaps),
          vshSnapSorter);
    snaplist->nsnaps -= deleted;

    ret = snaplist;
    snaplist = NULL;

cleanup:
    vshSnapshotListFree(snaplist);
    if (names)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}

static const char *
vshSnapshotListLookup(int id, bool parent, void *opaque)
{
    vshSnapshotListPtr snaplist = opaque;
    if (parent)
        return snaplist->snaps[id].parent;
    return virDomainSnapshotGetName(snaplist->snaps[id].snap);
}

/*
 * "snapshot-list" command
 */
static const vshCmdInfo info_snapshot_list[] = {
    {"help", N_("List snapshots for a domain")},
    {"desc", N_("Snapshot List")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_list[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"parent", VSH_OT_BOOL, 0, N_("add a column showing parent snapshot")},
    {"roots", VSH_OT_BOOL, 0, N_("list only snapshots without parents")},
    {"leaves", VSH_OT_BOOL, 0, N_("list only snapshots without children")},
    {"no-leaves", VSH_OT_BOOL, 0,
     N_("list only snapshots that are not leaves (with children)")},
    {"metadata", VSH_OT_BOOL, 0,
     N_("list only snapshots that have metadata that would prevent undefine")},
    {"no-metadata", VSH_OT_BOOL, 0,
     N_("list only snapshots that have no metadata managed by libvirt")},
    {"tree", VSH_OT_BOOL, 0, N_("list snapshots in a tree")},
    {"from", VSH_OT_DATA, 0, N_("limit list to children of given snapshot")},
    {"current", VSH_OT_BOOL, 0,
     N_("limit list to children of current snapshot")},
    {"descendants", VSH_OT_BOOL, 0, N_("with --from, list all descendants")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotList(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    bool show_parent = false;
    int i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *state = NULL;
    char *parent = NULL;
    long long creation_longlong;
    time_t creation_time_t;
    char timestr[100];
    struct tm time_info;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool leaves = vshCommandOptBool(cmd, "leaves");
    bool no_leaves = vshCommandOptBool(cmd, "no-leaves");
    const char *from = NULL;
    virDomainSnapshotPtr start = NULL;
    vshSnapshotListPtr snaplist = NULL;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if ((vshCommandOptBool(cmd, "from") ||
         vshCommandOptBool(cmd, "current")) &&
        vshLookupSnapshot(ctl, cmd, "from", true, dom, &start, &from) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "parent")) {
        if (vshCommandOptBool(cmd, "roots")) {
            vshError(ctl, "%s",
                     _("--parent and --roots are mutually exclusive"));
            goto cleanup;
        }
        if (tree) {
            vshError(ctl, "%s",
                     _("--parent and --tree are mutually exclusive"));
            goto cleanup;
        }
        show_parent = true;
    } else if (vshCommandOptBool(cmd, "roots")) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--roots and --tree are mutually exclusive"));
            goto cleanup;
        }
        if (from) {
            vshError(ctl, "%s",
                     _("--roots and --from are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
    }
    if (leaves) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--leaves and --tree are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_LEAVES;
    }
    if (no_leaves) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--no-leaves and --tree are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES;
    }

    if (vshCommandOptBool(cmd, "metadata")) {
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_METADATA;
    }
    if (vshCommandOptBool(cmd, "no-metadata")) {
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA;
    }

    if (vshCommandOptBool(cmd, "descendants")) {
        if (!from) {
            vshError(ctl, "%s",
                     _("--descendants requires either --from or --current"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    }

    if ((snaplist = vshSnapshotListCollect(ctl, dom, start, flags,
                                           tree)) == NULL)
        goto cleanup;

    if (!tree) {
        if (show_parent)
            vshPrintExtra(ctl, " %-20s %-25s %-15s %s",
                          _("Name"), _("Creation Time"), _("State"),
                          _("Parent"));
        else
            vshPrintExtra(ctl, " %-20s %-25s %s",
                          _("Name"), _("Creation Time"), _("State"));
        vshPrintExtra(ctl, "\n"
"------------------------------------------------------------\n");
    }

    if (!snaplist->nsnaps) {
        ret = true;
        goto cleanup;
    }

    if (tree) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            if (!snaplist->snaps[i].parent &&
                vshTreePrint(ctl, vshSnapshotListLookup, snaplist,
                             snaplist->nsnaps, i) < 0)
                goto cleanup;
        }
        ret = true;
        goto cleanup;
    }

    for (i = 0; i < snaplist->nsnaps; i++) {
        const char *name;

        /* free up memory from previous iterations of the loop */
        VIR_FREE(parent);
        VIR_FREE(state);
        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(xml);
        VIR_FREE(doc);

        snapshot = snaplist->snaps[i].snap;
        name = virDomainSnapshotGetName(snapshot);
        assert(name);

        doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
        if (!doc)
            continue;

        xml = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt);
        if (!xml)
            continue;

        if (show_parent)
            parent = virXPathString("string(/domainsnapshot/parent/name)",
                                    ctxt);

        state = virXPathString("string(/domainsnapshot/state)", ctxt);
        if (state == NULL)
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
                     name, timestr, state, parent);
        else
            vshPrint(ctl, " %-20s %-25s %s\n", name, timestr, state);
    }

    ret = true;

cleanup:
    /* this frees up memory from the last iteration of the loop */
    vshSnapshotListFree(snaplist);
    VIR_FREE(parent);
    VIR_FREE(state);
    if (start)
        virDomainSnapshotFree(start);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(doc);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-dumpxml" command
 */
static const vshCmdInfo info_snapshot_dumpxml[] = {
    {"help", N_("Dump XML for a domain snapshot")},
    {"desc", N_("Snapshot Dump XML")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("snapshot name")},
    {"security-info", VSH_OT_BOOL, 0,
     N_("include security sensitive information in XML dump")},
    {NULL, 0, 0, NULL}
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

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "snapshotname", &name) <= 0)
        goto cleanup;

    snapshot = virDomainSnapshotLookupByName(dom, name, 0);
    if (snapshot == NULL)
        goto cleanup;

    xml = virDomainSnapshotGetXMLDesc(snapshot, flags);
    if (!xml)
        goto cleanup;

    vshPrint(ctl, "%s", xml);

    ret = true;

cleanup:
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-parent" command
 */
static const vshCmdInfo info_snapshot_parent[] = {
    {"help", N_("Get the name of the parent of a snapshot")},
    {"desc", N_("Extract the snapshot's parent, if any")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_parent[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("find parent of snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("find parent of current snapshot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotParent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *parent = NULL;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

    if (vshGetSnapshotParent(ctl, snapshot, &parent) < 0)
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
    {"help", N_("Revert a domain to a snapshot")},
    {"desc", N_("Revert domain to snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_revert[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("revert to current snapshot")},
    {"running", VSH_OT_BOOL, 0, N_("after reverting, change state to running")},
    {"paused", VSH_OT_BOOL, 0, N_("after reverting, change state to paused")},
    {"force", VSH_OT_BOOL, 0, N_("try harder on risky reverts")},
    {NULL, 0, 0, NULL}
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

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
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
    {"help", N_("Delete a domain snapshot")},
    {"desc", N_("Snapshot Delete")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_delete[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("delete current snapshot")},
    {"children", VSH_OT_BOOL, 0, N_("delete snapshot and all children")},
    {"children-only", VSH_OT_BOOL, 0, N_("delete children but not snapshot")},
    {"metadata", VSH_OT_BOOL, 0,
     N_("delete only libvirt metadata, leaving snapshot contents behind")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotDelete(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
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
            vshPrint(ctl, _("Domain snapshot %s children deleted\n"), name);
        else
            vshPrint(ctl, _("Domain snapshot %s deleted\n"), name);
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
    {"snapshot-create", cmdSnapshotCreate, opts_snapshot_create,
     info_snapshot_create, 0},
    {"snapshot-create-as", cmdSnapshotCreateAs, opts_snapshot_create_as,
     info_snapshot_create_as, 0},
    {"snapshot-current", cmdSnapshotCurrent, opts_snapshot_current,
     info_snapshot_current, 0},
    {"snapshot-delete", cmdSnapshotDelete, opts_snapshot_delete,
     info_snapshot_delete, 0},
    {"snapshot-dumpxml", cmdSnapshotDumpXML, opts_snapshot_dumpxml,
     info_snapshot_dumpxml, 0},
    {"snapshot-edit", cmdSnapshotEdit, opts_snapshot_edit,
     info_snapshot_edit, 0},
    {"snapshot-info", cmdSnapshotInfo, opts_snapshot_info,
     info_snapshot_info, 0},
    {"snapshot-list", cmdSnapshotList, opts_snapshot_list,
     info_snapshot_list, 0},
    {"snapshot-parent", cmdSnapshotParent, opts_snapshot_parent,
     info_snapshot_parent, 0},
    {"snapshot-revert", cmdDomainSnapshotRevert, opts_snapshot_revert,
     info_snapshot_revert, 0},
    {NULL, NULL, NULL, NULL, 0}
};
