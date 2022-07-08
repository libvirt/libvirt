/*
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
#include "virsh-backup.h"
#include "virsh-util.h"

#include "internal.h"
#include "virfile.h"

/*
 * "backup-begin" command
 */
static const vshCmdInfo info_backup_begin[] = {
    {.name = "help",
     .data = N_("Start a disk backup of a live domain")
    },
    {.name = "desc",
     .data = N_("Use XML to start a full or incremental disk backup of a live "
                "domain, optionally creating a checkpoint")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_backup_begin[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "backupxml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("domain backup XML"),
    },
    {.name = "checkpointxml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("domain checkpoint XML"),
    },
    {.name = "reuse-external",
     .type = VSH_OT_BOOL,
     .help = N_("reuse files provided by caller"),
    },
    {.name = NULL}
};

static bool
cmdBackupBegin(vshControl *ctl,
               const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *backup_from = NULL;
    g_autofree char *backup_buffer = NULL;
    const char *check_from = NULL;
    g_autofree char *check_buffer = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "backupxml", &backup_from) < 0)
        return false;

    if (!backup_from) {
        backup_buffer = g_strdup("<domainbackup/>");
    } else {
        if (virFileReadAll(backup_from, VSH_MAX_XML_FILE, &backup_buffer) < 0) {
            vshSaveLibvirtError();
            return false;
        }
    }

    if (vshCommandOptStringReq(ctl, cmd, "checkpointxml", &check_from) < 0)
        return false;
    if (check_from) {
        if (virFileReadAll(check_from, VSH_MAX_XML_FILE, &check_buffer) < 0) {
            vshSaveLibvirtError();
            return false;
        }
    }

    if (virDomainBackupBegin(dom, backup_buffer, check_buffer, flags) < 0)
        return false;

    vshPrint(ctl, _("Backup started\n"));
    return true;
}


/*
 * "backup-dumpxml" command
 */
static const vshCmdInfo info_backup_dumpxml[] = {
    {.name = "help",
     .data = N_("Dump XML for an ongoing domain block backup job")
    },
    {.name = "desc",
     .data = N_("Backup Dump XML")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_backup_dumpxml[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
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
cmdBackupDumpXML(vshControl *ctl,
                 const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *xml = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virDomainBackupGetXMLDesc(dom, 0)))
        return false;

    return virshDumpXML(ctl, xml, "domain-backup", xpath, wrap);
}


const vshCmdDef backupCmds[] = {
    {.name = "backup-begin",
     .handler = cmdBackupBegin,
     .opts = opts_backup_begin,
     .info = info_backup_begin,
     .flags = 0
    },
    {.name = "backup-dumpxml",
     .handler = cmdBackupDumpXML,
     .opts = opts_backup_dumpxml,
     .info = info_backup_dumpxml,
     .flags = 0
    },
    {.name = NULL}
};
