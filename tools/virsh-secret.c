/*
 * virsh-secret.c: Commands to manage secret
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
 */

#include <config.h>
#include "virsh-secret.h"
#include "virsh-util.h"

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virutil.h"
#include "virsecret.h"
#include "virtime.h"
#include "vsh-table.h"
#include "virenum.h"
#include "virsecureerase.h"

static virSecretPtr
virshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, const char **name)
{
    virSecretPtr secret = NULL;
    const char *n = NULL;
    const char *optname = "secret";
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_DEBUG,
             "%s: found option <%s>: %s\n", cmd->def->name, optname, n);

    if (name != NULL)
        *name = n;

    secret = virSecretLookupByUUIDString(priv->conn, n);

    if (secret == NULL)
        vshError(ctl, _("failed to get secret '%1$s'"), n);

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
    VIRSH_COMMON_OPT_FILE(N_("file containing secret attributes in XML")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];
    bool ret = false;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_SECRET_DEFINE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (!(res = virSecretDefineXML(priv->conn, buffer, flags))) {
        vshError(ctl, _("Failed to set attributes from %1$s"), from);
        goto cleanup;
    }

    if (virSecretGetUUIDString(res, &(uuid[0])) < 0) {
        vshError(ctl, "%s", _("Failed to get UUID of created secret"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Secret %1$s created\n"), uuid);
    ret = true;

 cleanup:
    virshSecretFree(res);
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
     .help = N_("secret UUID"),
     .completer = virshSecretUUIDCompleter,
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
cmdSecretDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    g_autofree char *xml = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    secret = virshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    xml = virSecretGetXMLDesc(secret, 0);
    if (xml == NULL)
        goto cleanup;

    ret = virshDumpXML(ctl, xml, "secret", xpath, wrap);

 cleanup:
    virshSecretFree(secret);
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
     .help = N_("secret UUID"),
     .completer = virshSecretUUIDCompleter,
    },
    {.name = "file",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompletePathLocalExisting,
     .help = N_("read secret from file"),
    },
    {.name = "plain",
     .type = VSH_OT_BOOL,
     .help = N_("read the secret from file without converting from base64")
    },
    {.name = "interactive",
     .type = VSH_OT_BOOL,
     .help = N_("read the secret from the terminal")
    },
    {.name = "base64",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("base64-encoded secret value")
    },
    {.name = NULL}
};

static bool
cmdSecretSetValue(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshSecret) secret = NULL;
    const char *base64 = NULL;
    const char *filename = NULL;
    g_autofree char *secret_val = NULL;
    size_t secret_len = 0;
    bool plain = vshCommandOptBool(cmd, "plain");
    bool interactive = vshCommandOptBool(cmd, "interactive");
    int res;

    VSH_EXCLUSIVE_OPTIONS("file", "base64");
    VSH_EXCLUSIVE_OPTIONS("plain", "base64");
    VSH_EXCLUSIVE_OPTIONS("interactive", "base64");
    VSH_EXCLUSIVE_OPTIONS("interactive", "plain");
    VSH_EXCLUSIVE_OPTIONS("interactive", "file");

    if (!(secret = virshCommandOptSecret(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "base64", &base64) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &filename) < 0)
        return false;

    if (base64) {
        /* warn users that the --base64 option passed from command line is wrong */
        vshError(ctl, _("Passing secret value as command-line argument is insecure!"));
        secret_val = g_strdup(base64);
        secret_len = strlen(secret_val);
    } else if (filename) {
        ssize_t read_ret;
        if ((read_ret = virFileReadAll(filename, 1024, &secret_val)) < 0) {
            vshSaveLibvirtError();
            return false;
        }

        secret_len = read_ret;
    } else if (interactive) {
        vshPrint(ctl, "%s", _("Enter new value for secret:"));
        fflush(stdout);

        if (!(secret_val = virGetPassword())) {
            vshError(ctl, "%s", _("Failed to read secret"));
            return false;
        }
        secret_len = strlen(secret_val);
        plain = true;
    } else {
        vshError(ctl, _("Input secret value is missing"));
        return false;
    }

    if (!plain) {
        g_autofree char *tmp = g_steal_pointer(&secret_val);
        size_t tmp_len = secret_len;

        secret_val = (char *) g_base64_decode(tmp, &secret_len);
        virSecureErase(tmp, tmp_len);
    }

    res = virSecretSetValue(secret, (unsigned char *) secret_val, secret_len, 0);
    virSecureErase(secret_val, secret_len);

    if (res != 0) {
        vshError(ctl, "%s", _("Failed to set secret value"));
        return false;
    }
    vshPrintExtra(ctl, "%s", _("Secret value set\n"));
    return true;
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
     .help = N_("secret UUID"),
     .completer = virshSecretUUIDCompleter,
    },
    {.name = "plain",
     .type = VSH_OT_BOOL,
     .help = N_("get value without converting to base64")
    },
    {.name = NULL}
};

static bool
cmdSecretGetValue(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshSecret) secret = NULL;
    g_autofree unsigned char *value = NULL;
    size_t value_size;
    bool plain = vshCommandOptBool(cmd, "plain");

    if (!(secret = virshCommandOptSecret(ctl, cmd, NULL)))
        return false;

    if (!(value = virSecretGetValue(secret, &value_size, 0)))
        return false;

    if (plain) {
        if (fwrite(value, 1, value_size, stdout) != value_size) {
            virSecureErase(value, value_size);
            vshError(ctl, "failed to write secret");
            return false;
        }
    } else {
        g_autofree char *base64 = g_base64_encode(value, value_size);

        vshPrint(ctl, "%s", base64);
        virSecureEraseString(base64);
    }

    virSecureErase(value, value_size);
    return true;
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
     .help = N_("secret UUID"),
     .completer = virshSecretUUIDCompleter,
    },
    {.name = NULL}
};

static bool
cmdSecretUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    const char *uuid;

    secret = virshCommandOptSecret(ctl, cmd, &uuid);
    if (secret == NULL)
        return false;

    if (virSecretUndefine(secret) < 0) {
        vshError(ctl, _("Failed to delete secret %1$s"), uuid);
        goto cleanup;
    }
    vshPrintExtra(ctl, _("Secret %1$s deleted\n"), uuid);
    ret = true;

 cleanup:
    virshSecretFree(secret);
    return ret;
}

static int
virshSecretSorter(const void *a, const void *b)
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

struct virshSecretList {
    virSecretPtr *secrets;
    size_t nsecrets;
};

static void
virshSecretListFree(struct virshSecretList *list)
{
    size_t i;

    if (list && list->secrets) {
        for (i = 0; i < list->nsecrets; i++)
            virshSecretFree(list->secrets[i]);

        g_free(list->secrets);
    }
    g_free(list);
}

static struct virshSecretList *
virshSecretListCollect(vshControl *ctl,
                       unsigned int flags)
{
    struct virshSecretList *list = g_new0(struct virshSecretList, 1);
    size_t i;
    int ret;
    virSecretPtr secret;
    bool success = false;
    size_t deleted = 0;
    int nsecrets = 0;
    char **uuids = NULL;
    virshControl *priv = ctl->privData;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virConnectListAllSecrets(priv->conn,
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

    nsecrets = virConnectNumOfSecrets(priv->conn);
    if (nsecrets < 0) {
        vshError(ctl, "%s", _("Failed to count secrets"));
        goto cleanup;
    }

    if (nsecrets == 0)
        return list;

    uuids = g_new0(char *, nsecrets);

    nsecrets = virConnectListSecrets(priv->conn, uuids, nsecrets);
    if (nsecrets < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        goto cleanup;
    }

    list->secrets = g_new0(virSecretPtr, nsecrets);
    list->nsecrets = 0;

    /* get the secrets */
    for (i = 0; i < nsecrets; i++) {
        if (!(secret = virSecretLookupByUUIDString(priv->conn, uuids[i])))
            continue;
        list->secrets[list->nsecrets++] = secret;
    }

    /* truncate secrets that weren't found */
    deleted = nsecrets - list->nsecrets;

 finished:
    /* sort the list */
    if (list->secrets && list->nsecrets)
        qsort(list->secrets, list->nsecrets,
              sizeof(*list->secrets), virshSecretSorter);

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
        g_clear_pointer(&list, virshSecretListFree);
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
cmdSecretList(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    size_t i;
    struct virshSecretList *list = NULL;
    bool ret = false;
    unsigned int flags = 0;
    g_autoptr(vshTable) table = NULL;

    if (vshCommandOptBool(cmd, "ephemeral"))
        flags |= VIR_CONNECT_LIST_SECRETS_EPHEMERAL;

    if (vshCommandOptBool(cmd, "no-ephemeral"))
        flags |= VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL;

    if (vshCommandOptBool(cmd, "private"))
        flags |= VIR_CONNECT_LIST_SECRETS_PRIVATE;

    if (vshCommandOptBool(cmd, "no-private"))
        flags |= VIR_CONNECT_LIST_SECRETS_NO_PRIVATE;

    if (!(list = virshSecretListCollect(ctl, flags)))
        return false;

    table = vshTableNew(_("UUID"), _("Usage"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < list->nsecrets; i++) {
        virSecretPtr sec = list->secrets[i];
        int usageType = virSecretGetUsageType(sec);
        const char *usageStr = virSecretUsageTypeToString(usageType);
        char uuid[VIR_UUID_STRING_BUFLEN];
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        g_autofree char *usage = NULL;

        if (virSecretGetUUIDString(sec, uuid) < 0) {
            vshError(ctl, "%s", _("Failed to get uuid of secret"));
            goto cleanup;
        }

        if (usageType) {
            virBufferStrcat(&buf, usageStr, " ",
                            virSecretGetUsageID(sec), NULL);
            usage = virBufferContentAndReset(&buf);
            if (!usage)
                goto cleanup;

            if (vshTableRowAppend(table, uuid, usage, NULL) < 0)
                goto cleanup;
        } else {
            if (vshTableRowAppend(table, uuid, _("Unused"), NULL) < 0)
                goto cleanup;
        }
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    virshSecretListFree(list);
    return ret;
}

/*
 * "Secret-event" command
 */
VIR_ENUM_DECL(virshSecretEvent);
VIR_ENUM_IMPL(virshSecretEvent,
              VIR_SECRET_EVENT_LAST,
              N_("Defined"),
              N_("Undefined"));

static const char *
virshSecretEventToString(int event)
{
    const char *str = virshSecretEventTypeToString(event);
    return str ? _(str) : _("unknown");
}

struct virshSecretEventData {
    vshControl *ctl;
    bool loop;
    bool timestamp;
    int count;
    virshSecretEventCallback *cb;
};
typedef struct virshSecretEventData virshSecretEventData;

static void
vshEventLifecyclePrint(virConnectPtr conn G_GNUC_UNUSED,
                       virSecretPtr secret,
                       int event,
                       int detail G_GNUC_UNUSED,
                       void *opaque)
{
    virshSecretEventData *data = opaque;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!data->loop && data->count)
        return;

    virSecretGetUUIDString(secret, uuid);
    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%1$s: event 'lifecycle' for secret %2$s: %3$s\n"),
                 timestamp, uuid, virshSecretEventToString(event));
    } else {
        vshPrint(data->ctl, _("event 'lifecycle' for secret %1$s: %2$s\n"),
                 uuid, virshSecretEventToString(event));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

static void
vshEventGenericPrint(virConnectPtr conn G_GNUC_UNUSED,
                     virSecretPtr secret,
                     void *opaque)
{
    virshSecretEventData *data = opaque;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!data->loop && data->count)
        return;

    virSecretGetUUIDString(secret, uuid);

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, _("%1$s: event '%2$s' for secret %3$s\n"),
                 timestamp,
                 data->cb->name,
                 uuid);
    } else {
        vshPrint(data->ctl, _("event '%1$s' for secret %2$s\n"),
                 data->cb->name,
                 uuid);
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

virshSecretEventCallback virshSecretEventCallbacks[] = {
    { "lifecycle",
      VIR_SECRET_EVENT_CALLBACK(vshEventLifecyclePrint), },
    { "value-changed", vshEventGenericPrint, },
};
G_STATIC_ASSERT(VIR_SECRET_EVENT_ID_LAST == G_N_ELEMENTS(virshSecretEventCallbacks));

static const vshCmdInfo info_secret_event[] = {
    {.name = "help",
     .data = N_("Secret Events")
    },
    {.name = "desc",
     .data = N_("List event types, or wait for secret events to occur")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_secret_event[] = {
    {.name = "secret",
     .type = VSH_OT_STRING,
     .help = N_("filter by secret name or uuid"),
     .completer = virshSecretUUIDCompleter,
    },
    {.name = "event",
     .type = VSH_OT_STRING,
     .completer = virshSecretEventNameCompleter,
     .help = N_("which event type to wait for")
    },
    {.name = "loop",
     .type = VSH_OT_BOOL,
     .help = N_("loop until timeout or interrupt, rather than one-shot")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("timeout seconds")
    },
    {.name = "list",
     .type = VSH_OT_BOOL,
     .help = N_("list valid event types")
    },
    {.name = "timestamp",
     .type = VSH_OT_BOOL,
     .help = N_("show timestamp for each printed event")
    },
    {.name = NULL}
};

static bool
cmdSecretEvent(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret = NULL;
    bool ret = false;
    int eventId = -1;
    int timeout = 0;
    virshSecretEventData data;
    const char *eventName = NULL;
    int event;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "list")) {
        size_t i;

        for (i = 0; i < VIR_SECRET_EVENT_ID_LAST; i++)
            vshPrint(ctl, "%s\n", virshSecretEventCallbacks[i].name);
        return true;
    }

    if (vshCommandOptStringReq(ctl, cmd, "event", &eventName) < 0)
        return false;
    if (!eventName) {
        vshError(ctl, "%s", _("either --list or --event <type> is required"));
        return false;
    }
    for (event = 0; event < VIR_SECRET_EVENT_ID_LAST; event++)
        if (STREQ(eventName, virshSecretEventCallbacks[event].name))
            break;
    if (event == VIR_SECRET_EVENT_ID_LAST) {
        vshError(ctl, _("unknown event type %1$s"), eventName);
        return false;
    }

    data.ctl = ctl;
    data.loop = vshCommandOptBool(cmd, "loop");
    data.timestamp = vshCommandOptBool(cmd, "timestamp");
    data.count = 0;
    data.cb = &virshSecretEventCallbacks[event];
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (vshCommandOptBool(cmd, "secret"))
        secret = virshCommandOptSecret(ctl, cmd, NULL);
    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    if ((eventId = virConnectSecretEventRegisterAny(priv->conn, secret, event,
                                                    data.cb->cb,
                                                    &data, NULL)) < 0)
        goto cleanup;
    switch (vshEventWait(ctl)) {
    case VSH_EVENT_INTERRUPT:
        vshPrint(ctl, "%s", _("event loop interrupted\n"));
        break;
    case VSH_EVENT_TIMEOUT:
        vshPrint(ctl, "%s", _("event loop timed out\n"));
        break;
    case VSH_EVENT_DONE:
        break;
    default:
        goto cleanup;
    }
    vshPrint(ctl, _("events received: %1$d\n"), data.count);
    if (data.count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (eventId >= 0 &&
        virConnectSecretEventDeregisterAny(priv->conn, eventId) < 0)
        ret = false;
    virshSecretFree(secret);
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
    {.name = "secret-event",
     .handler = cmdSecretEvent,
     .opts = opts_secret_event,
     .info = info_secret_event,
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
