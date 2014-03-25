/*
 * virsh-secret.c: Commands to manage secret
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
#include "virsh-secret.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "base64.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virutil.h"
#include "virxml.h"
#include "conf/secret_conf.h"

static virSecretPtr
vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, const char **name)
{
    virSecretPtr secret = NULL;
    const char *n = NULL;
    const char *optname = "secret";

    if (!vshCmdHasOption(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_DEBUG,
             "%s: found option <%s>: %s\n", cmd->def->name, optname, n);

    if (name != NULL)
        *name = n;

    secret = virSecretLookupByUUIDString(ctl->conn, n);

    if (secret == NULL)
        vshError(ctl, _("failed to get secret '%s'"), n);

    return secret;
}

/*
 * "secret-define" command
 */
static const vshCmdInfo info_secret_define[] = {
    {.name = "help",
     .data = N_("define or modify a secret from an XML file")
    },
    {.name = "desc",
     .data = N_("Define or modify a secret.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_define[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing secret attributes in XML")
    },
    {.name = NULL}
};

static bool
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    char *buffer;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];
    bool ret = false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (!(res = virSecretDefineXML(ctl->conn, buffer, 0))) {
        vshError(ctl, _("Failed to set attributes from %s"), from);
        goto cleanup;
    }

    if (virSecretGetUUIDString(res, &(uuid[0])) < 0) {
        vshError(ctl, "%s", _("Failed to get UUID of created secret"));
        goto cleanup;
    }

    vshPrint(ctl, _("Secret %s created\n"), uuid);
    ret = true;

 cleanup:
    VIR_FREE(buffer);
    if (res)
        virSecretFree(res);
    return ret;
}

/*
 * "secret-dumpxml" command
 */
static const vshCmdInfo info_secret_dumpxml[] = {
    {.name = "help",
     .data = N_("secret attributes in XML")
    },
    {.name = "desc",
     .data = N_("Output attributes of a secret as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_dumpxml[] = {
    {.name = "secret",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("secret UUID")
    },
    {.name = NULL}
};

static bool
cmdSecretDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    char *xml;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    xml = virSecretGetXMLDesc(secret, 0);
    if (xml == NULL)
        goto cleanup;
    vshPrint(ctl, "%s", xml);
    VIR_FREE(xml);
    ret = true;

 cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-set-value" command
 */
static const vshCmdInfo info_secret_set_value[] = {
    {.name = "help",
     .data = N_("set a secret value")
    },
    {.name = "desc",
     .data = N_("Set a secret value.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_set_value[] = {
    {.name = "secret",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("secret UUID")
    },
    {.name = "base64",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("base64-encoded secret value")
    },
    {.name = NULL}
};

static bool
cmdSecretSetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    size_t value_size;
    const char *base64 = NULL;
    char *value;
    int res;
    bool ret = false;

    if (!(secret = vshCommandOptSecret(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "base64", &base64) < 0)
        goto cleanup;

    if (!base64_decode_alloc(base64, strlen(base64), &value, &value_size)) {
        vshError(ctl, "%s", _("Invalid base64 data"));
        goto cleanup;
    }
    if (value == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }

    res = virSecretSetValue(secret, (unsigned char *)value, value_size, 0);
    memset(value, 0, value_size);
    VIR_FREE(value);

    if (res != 0) {
        vshError(ctl, "%s", _("Failed to set secret value"));
        goto cleanup;
    }
    vshPrint(ctl, "%s", _("Secret value set\n"));
    ret = true;

 cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-get-value" command
 */
static const vshCmdInfo info_secret_get_value[] = {
    {.name = "help",
     .data = N_("Output a secret value")
    },
    {.name = "desc",
     .data = N_("Output a secret value to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_get_value[] = {
    {.name = "secret",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("secret UUID")
    },
    {.name = NULL}
};

static bool
cmdSecretGetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    char *base64;
    unsigned char *value;
    size_t value_size;
    bool ret = false;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    value = virSecretGetValue(secret, &value_size, 0);
    if (value == NULL)
        goto cleanup;

    base64_encode_alloc((char *)value, value_size, &base64);
    memset(value, 0, value_size);
    VIR_FREE(value);

    if (base64 == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }
    vshPrint(ctl, "%s", base64);
    memset(base64, 0, strlen(base64));
    VIR_FREE(base64);
    ret = true;

 cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-undefine" command
 */
static const vshCmdInfo info_secret_undefine[] = {
    {.name = "help",
     .data = N_("undefine a secret")
    },
    {.name = "desc",
     .data = N_("Undefine a secret.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_undefine[] = {
    {.name = "secret",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("secret UUID")
    },
    {.name = NULL}
};

static bool
cmdSecretUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    const char *uuid;

    secret = vshCommandOptSecret(ctl, cmd, &uuid);
    if (secret == NULL)
        return false;

    if (virSecretUndefine(secret) < 0) {
        vshError(ctl, _("Failed to delete secret %s"), uuid);
        goto cleanup;
    }
    vshPrint(ctl, _("Secret %s deleted\n"), uuid);
    ret = true;

 cleanup:
    virSecretFree(secret);
    return ret;
}

static int
vshSecretSorter(const void *a, const void *b)
{
    virSecretPtr *sa = (virSecretPtr *) a;
    virSecretPtr *sb = (virSecretPtr *) b;
    char uuid_sa[VIR_UUID_STRING_BUFLEN];
    char uuid_sb[VIR_UUID_STRING_BUFLEN];

    if (*sa && !*sb)
        return -1;

    if (!*sa)
        return *sb != NULL;

    virSecretGetUUIDString(*sa, uuid_sa);
    virSecretGetUUIDString(*sb, uuid_sb);

    return vshStrcasecmp(uuid_sa, uuid_sb);
}

struct vshSecretList {
    virSecretPtr *secrets;
    size_t nsecrets;
};
typedef struct vshSecretList *vshSecretListPtr;

static void
vshSecretListFree(vshSecretListPtr list)
{
    size_t i;

    if (list && list->secrets) {
        for (i = 0; i < list->nsecrets; i++) {
            if (list->secrets[i])
                virSecretFree(list->secrets[i]);
        }
        VIR_FREE(list->secrets);
    }
    VIR_FREE(list);
}

static vshSecretListPtr
vshSecretListCollect(vshControl *ctl,
                     unsigned int flags)
{
    vshSecretListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    int ret;
    virSecretPtr secret;
    bool success = false;
    size_t deleted = 0;
    int nsecrets = 0;
    char **uuids = NULL;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllSecrets(ctl->conn,
                                        &list->secrets,
                                        flags)) >= 0) {
        list->nsecrets = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    /* there was an error during the call */
    vshError(ctl, "%s", _("Failed to list node secrets"));
    goto cleanup;


 fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    if (flags) {
        vshError(ctl, "%s", _("Filtering is not supported by this libvirt"));
        goto cleanup;
    }

    nsecrets = virConnectNumOfSecrets(ctl->conn);
    if (nsecrets < 0) {
        vshError(ctl, "%s", _("Failed to count secrets"));
        goto cleanup;
    }

    if (nsecrets == 0)
        return list;

    uuids = vshMalloc(ctl, sizeof(char *) * nsecrets);

    nsecrets = virConnectListSecrets(ctl->conn, uuids, nsecrets);
    if (nsecrets < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        goto cleanup;
    }

    list->secrets = vshMalloc(ctl, sizeof(virSecretPtr) * (nsecrets));
    list->nsecrets = 0;

    /* get the secrets */
    for (i = 0; i < nsecrets; i++) {
        if (!(secret = virSecretLookupByUUIDString(ctl->conn, uuids[i])))
            continue;
        list->secrets[list->nsecrets++] = secret;
    }

    /* truncate secrets that weren't found */
    deleted = nsecrets - list->nsecrets;

 finished:
    /* sort the list */
    if (list->secrets && list->nsecrets)
        qsort(list->secrets, list->nsecrets,
              sizeof(*list->secrets), vshSecretSorter);

    /* truncate the list for not found secret objects */
    if (deleted)
        VIR_SHRINK_N(list->secrets, list->nsecrets, deleted);

    success = true;

 cleanup:
    if (nsecrets > 0) {
        for (i = 0; i < nsecrets; i++)
            VIR_FREE(uuids[i]);
        VIR_FREE(uuids);
    }

    if (!success) {
        vshSecretListFree(list);
        list = NULL;
    }

    return list;
}

/*
 * "secret-list" command
 */
static const vshCmdInfo info_secret_list[] = {
    {.name = "help",
     .data = N_("list secrets")
    },
    {.name = "desc",
     .data = N_("Returns a list of secrets")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_list[] = {
    {.name = "ephemeral",
     .type = VSH_OT_BOOL,
     .help = N_("list ephemeral secrets")
    },
    {.name = "no-ephemeral",
     .type = VSH_OT_BOOL,
     .help = N_("list non-ephemeral secrets")
    },
    {.name = "private",
     .type = VSH_OT_BOOL,
     .help = N_("list private secrets")
    },
    {.name = "no-private",
     .type = VSH_OT_BOOL,
     .help = N_("list non-private secrets")
    },
    {.name = NULL}
};

static bool
cmdSecretList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    size_t i;
    vshSecretListPtr list = NULL;
    bool ret = false;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "ephemeral"))
        flags |= VIR_CONNECT_LIST_SECRETS_EPHEMERAL;

    if (vshCommandOptBool(cmd, "no-ephemeral"))
        flags |= VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL;

    if (vshCommandOptBool(cmd, "private"))
        flags |= VIR_CONNECT_LIST_SECRETS_PRIVATE;

    if (vshCommandOptBool(cmd, "no-private"))
        flags |= VIR_CONNECT_LIST_SECRETS_NO_PRIVATE;

    if (!(list = vshSecretListCollect(ctl, flags)))
        return false;

    vshPrintExtra(ctl, " %-36s  %s\n", _("UUID"), _("Usage"));
    vshPrintExtra(ctl, "----------------------------------------"
                       "----------------------------------------\n");

    for (i = 0; i < list->nsecrets; i++) {
        virSecretPtr sec = list->secrets[i];
        int usageType = virSecretGetUsageType(sec);
        const char *usageStr = virSecretUsageTypeTypeToString(usageType);
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virSecretGetUUIDString(list->secrets[i], uuid) < 0) {
            vshError(ctl, "%s", _("Failed to get uuid of secret"));
            goto cleanup;
        }

        if (usageType) {
            vshPrint(ctl, " %-36s  %s %s\n",
                     uuid, usageStr,
                     virSecretGetUsageID(sec));
        } else {
            vshPrint(ctl, " %-36s  %s\n",
                     uuid, _("Unused"));
        }
    }

    ret = true;

 cleanup:
    vshSecretListFree(list);
    return ret;
}

const vshCmdDef secretCmds[] = {
    {.name = "secret-define",
     .handler = cmdSecretDefine,
     .opts = opts_secret_define,
     .info = info_secret_define,
     .flags = 0
    },
    {.name = "secret-dumpxml",
     .handler = cmdSecretDumpXML,
     .opts = opts_secret_dumpxml,
     .info = info_secret_dumpxml,
     .flags = 0
    },
    {.name = "secret-get-value",
     .handler = cmdSecretGetValue,
     .opts = opts_secret_get_value,
     .info = info_secret_get_value,
     .flags = 0
    },
    {.name = "secret-list",
     .handler = cmdSecretList,
     .opts = opts_secret_list,
     .info = info_secret_list,
     .flags = 0
    },
    {.name = "secret-set-value",
     .handler = cmdSecretSetValue,
     .opts = opts_secret_set_value,
     .info = info_secret_set_value,
     .flags = 0
    },
    {.name = "secret-undefine",
     .handler = cmdSecretUndefine,
     .opts = opts_secret_undefine,
     .info = info_secret_undefine,
     .flags = 0
    },
    {.name = NULL}
};
