/*
 * virsh-secret.c: Commands to manage secret
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
#include "virsh-secret.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "base64.h"
#include "buf.h"
#include "memory.h"
#include "util.h"
#include "xml.h"

static virSecretPtr
vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, const char **name)
{
    virSecretPtr secret = NULL;
    const char *n = NULL;
    const char *optname = "secret";

    if (!vshCmdHasOption(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
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
    {"help", N_("define or modify a secret from an XML file")},
    {"desc", N_("Define or modify a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing secret attributes in XML")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    char *buffer;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    res = virSecretDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (res == NULL) {
        vshError(ctl, _("Failed to set attributes from %s"), from);
        return false;
    }
    if (virSecretGetUUIDString(res, &(uuid[0])) < 0) {
        vshError(ctl, "%s", _("Failed to get UUID of created secret"));
        virSecretFree(res);
        return false;
    }
    vshPrint(ctl, _("Secret %s created\n"), uuid);
    virSecretFree(res);
    return true;
}

/*
 * "secret-dumpxml" command
 */
static const vshCmdInfo info_secret_dumpxml[] = {
    {"help", N_("secret attributes in XML")},
    {"desc", N_("Output attributes of a secret as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_dumpxml[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
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
    {"help", N_("set a secret value")},
    {"desc", N_("Set a secret value.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_set_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {"base64", VSH_OT_DATA, VSH_OFLAG_REQ, N_("base64-encoded secret value")},
    {NULL, 0, 0, NULL}
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

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    if (vshCommandOptString(cmd, "base64", &base64) <= 0)
        goto cleanup;

    if (!base64_decode_alloc(base64, strlen(base64), &value, &value_size)) {
        vshError(ctl, "%s", _("Invalid base64 data"));
        goto cleanup;
    }
    if (value == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        return false;
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
    {"help", N_("Output a secret value")},
    {"desc", N_("Output a secret value to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_get_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
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
    {"help", N_("undefine a secret")},
    {"desc", N_("Undefine a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_undefine[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
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
    int i;

    if (list && list->nsecrets) {
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
    int i;
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
    for (i = 0; i < nsecrets ; i++) {
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
    for (i = 0; i < nsecrets; i++)
        VIR_FREE(uuids[i]);
    VIR_FREE(uuids);

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
    {"help", N_("list secrets")},
    {"desc", N_("Returns a list of secrets")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_list[] = {
    {"ephemeral", VSH_OT_BOOL, 0, N_("list ephemeral secrets")},
    {"no-ephemeral", VSH_OT_BOOL, 0, N_("list non-ephemeral secrets")},
    {"private", VSH_OT_BOOL, 0, N_("list private secrets")},
    {"no-private", VSH_OT_BOOL, 0, N_("list non-private secrets")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int i;
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

    vshPrintExtra(ctl, "%-36s %s\n", _("UUID"), _("Usage"));
    vshPrintExtra(ctl, "-----------------------------------------------------------\n");

    for (i = 0; i < list->nsecrets; i++) {
        virSecretPtr sec = list->secrets[i];
        const char *usageType = NULL;

        switch (virSecretGetUsageType(sec)) {
        case VIR_SECRET_USAGE_TYPE_VOLUME:
            usageType = _("Volume");
            break;
        }

        char uuid[VIR_UUID_STRING_BUFLEN];
        if (virSecretGetUUIDString(list->secrets[i], uuid) < 0) {
            vshError(ctl, "%s", _("Failed to get uuid of secret"));
            goto cleanup;
        }

        if (usageType) {
            vshPrint(ctl, "%-36s %s %s\n",
                     uuid, usageType,
                     virSecretGetUsageID(sec));
        } else {
            vshPrint(ctl, "%-36s %s\n",
                     uuid, _("Unused"));
        }
    }

    ret = true;

cleanup:
    vshSecretListFree(list);
    return ret;
}

const vshCmdDef secretCmds[] = {
    {"secret-define", cmdSecretDefine, opts_secret_define,
     info_secret_define, 0},
    {"secret-dumpxml", cmdSecretDumpXML, opts_secret_dumpxml,
     info_secret_dumpxml, 0},
    {"secret-get-value", cmdSecretGetValue, opts_secret_get_value,
     info_secret_get_value, 0},
    {"secret-list", cmdSecretList, opts_secret_list, info_secret_list, 0},
    {"secret-set-value", cmdSecretSetValue, opts_secret_set_value,
     info_secret_set_value, 0},
    {"secret-undefine", cmdSecretUndefine, opts_secret_undefine,
     info_secret_undefine, 0},
    {NULL, NULL, NULL, NULL, 0}
};
