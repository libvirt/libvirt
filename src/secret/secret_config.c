/*
 * secret_config.c: secret.conf config file handling
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <fcntl.h>
#include "configmake.h"
#include "datatypes.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virutil.h"
#include "virsecureerase.h"
#include "secret_config.h"


#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("secret.secret_config");

static virClass *virSecretDaemonConfigClass;
static void virSecretDaemonConfigDispose(void *obj);

static int
virSecretConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSecretDaemonConfig, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virSecretConfig);


int
virSecretDaemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        *configfile = g_strdup(SYSCONFDIR "/libvirt/secret.conf");
    } else {
        g_autofree char *configdir = NULL;

        configdir = virGetUserConfigDirectory();

        *configfile = g_strdup_printf("%s/secret.conf", configdir);
    }

    return 0;
}


static int
virSecretLoadDaemonConfig(virSecretDaemonConfig *cfg,
                          const char *filename)
{
    g_autoptr(virConf) conf = NULL;
    int res;

    if (virFileExists(filename)) {
        conf = virConfReadFile(filename, 0);
        if (!conf)
            return -1;
        res = virConfGetValueBool(conf, "encrypt_data", &cfg->encryptData);
        if (res < 0) {
            return -1;
        } else if (res == 1) {
            cfg->encryptDataWasSet = true;
        } else {
            cfg->encryptDataWasSet = false;
        }

        if (virConfGetValueString(conf, "secrets_encryption_key",
                                  &cfg->secretsEncryptionKeyPath) < 0) {
            return -1;
        }
    }
    return 0;
}


static int
virGetSecretsEncryptionKey(virSecretDaemonConfig *cfg,
                           uint8_t **secretsEncryptionKey,
                           size_t *secretsKeyLen)
{
    VIR_AUTOCLOSE fd = -1;
    int encryptionKeyLength;

    if ((encryptionKeyLength = virFileReadAll(cfg->secretsEncryptionKeyPath,
                                              VIR_SECRETS_ENCRYPTION_KEY_LEN,
                                              (char**)secretsEncryptionKey)) < 0) {
        return -1;
    }
    if (encryptionKeyLength != VIR_SECRETS_ENCRYPTION_KEY_LEN) {
        virReportError(VIR_ERR_INVALID_ENCR_KEY_SECRET,
                       _("Encryption key length must be '%1$d' '%2$s'"),
                       VIR_SECRETS_ENCRYPTION_KEY_LEN,
                       cfg->secretsEncryptionKeyPath);
        return -1;
    }

    *secretsKeyLen = (size_t)encryptionKeyLength;
    return 0;
}


virSecretDaemonConfig *
virSecretDaemonConfigNew(bool privileged)
{
    g_autoptr(virSecretDaemonConfig) cfg = NULL;
    g_autofree char *configdir = NULL;
    g_autofree char *configfile = NULL;
    g_autofree char *rundir = NULL;
    const char *credentialsDirectory;

    if (virSecretConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virSecretDaemonConfigClass)))
        return NULL;

    if (virSecretDaemonConfigFilePath(privileged, &configfile) < 0)
        return NULL;

    if (virSecretLoadDaemonConfig(cfg, configfile) < 0)
        return NULL;

    credentialsDirectory = getenv("CREDENTIALS_DIRECTORY");

    if (!cfg->secretsEncryptionKeyPath && credentialsDirectory) {
        cfg->secretsEncryptionKeyPath = g_strdup_printf("%s/secrets-encryption-key",
                                                        credentialsDirectory);
        if (!virFileExists(cfg->secretsEncryptionKeyPath)) {
            g_clear_pointer(&cfg->secretsEncryptionKeyPath, g_free);
        }
    }

    if (!cfg->encryptDataWasSet) {
        if (!cfg->secretsEncryptionKeyPath) {
            /* No path specified by user or environment, disable encryption */
            cfg->encryptData = false;
        } else {
            cfg->encryptData = true;
        }
    } else {
        if (cfg->encryptData) {
            if (!cfg->secretsEncryptionKeyPath) {
                /* Built-in default path must be used */
                rundir = virGetUserRuntimeDirectory();
                cfg->secretsEncryptionKeyPath = g_strdup_printf("%s/secrets/encryption-key",
                                                                rundir);
            }
        }
    }
    VIR_DEBUG("Secrets encryption key path: %s", NULLSTR(cfg->secretsEncryptionKeyPath));

    if (cfg->encryptData) {
        if (virGetSecretsEncryptionKey(cfg,
                                       &cfg->secretsEncryptionKey,
                                       &cfg->secretsKeyLen) < 0) {
            return NULL;
        }
    }
    return g_steal_pointer(&cfg);
}


static void
virSecretDaemonConfigDispose(void *obj)
{
    virSecretDaemonConfig *cfg = obj;

    virSecureErase(cfg->secretsEncryptionKey, cfg->secretsKeyLen);
    g_free(cfg->secretsEncryptionKeyPath);
}
