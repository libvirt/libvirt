/*
 * secret_config.h: secret.conf config file handling
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "internal.h"
#include "virinhibitor.h"
#include "secret_event.h"
#define VIR_SECRETS_ENCRYPTION_KEY_LEN 32

typedef struct _virSecretDaemonConfig virSecretDaemonConfig;
struct _virSecretDaemonConfig {
    virObject parent;
    /* secrets encryption key path from secret.conf file */
    char *secretsEncryptionKeyPath;

    /* Store the key to encrypt secrets on the disk */
    unsigned char *secretsEncryptionKey;

    size_t secretsKeyLen;

    /* Indicates if the newly written secrets are encrypted or not.
     */
    bool encryptData;

    /* Indicates if the config file has encrypt_data set or not.
     */
    bool encryptDataWasSet;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSecretDaemonConfig, virObjectUnref);

int virSecretDaemonConfigFilePath(bool privileged, char **configfile);
virSecretDaemonConfig *virSecretDaemonConfigNew(bool privileged);
int virSecretDaemonConfigLoadFile(virSecretDaemonConfig *data,
                                  const char *filename,
                                  bool allow_missing);
