/*
 * virnetlibsshsession.c: ssh network transport provider based on libssh
 *
 * Copyright (C) 2012-2016 Red Hat, Inc.
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
#include <libssh/libssh.h>

#include "virnetlibsshsession.h"

#include "internal.h"
#include "viralloc.h"
#include "virlog.h"
#include "configmake.h"
#include "virutil.h"
#include "virerror.h"
#include "virobject.h"
#include "virstring.h"
#include "virauth.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_LIBSSH

VIR_LOG_INIT("rpc.netlibsshsession");

#define VIR_NET_LIBSSH_BUFFER_SIZE  1024

/* TRACE_LIBSSH=<level> enables tracing in libssh itself.
 * The meaning of <level> is described here:
 * http://api.libssh.org/master/group__libssh__log.html
 *
 * The LIBVIRT_LIBSSH_DEBUG environment variable can be used
 * to set/override the level of libssh debug.
 */
#define TRACE_LIBSSH  0

typedef enum {
    VIR_NET_LIBSSH_STATE_NEW,
    VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE,
    VIR_NET_LIBSSH_STATE_CLOSED,
    VIR_NET_LIBSSH_STATE_ERROR,
    VIR_NET_LIBSSH_STATE_ERROR_REMOTE,
} virNetLibsshSessionState;

typedef enum {
    VIR_NET_LIBSSH_AUTH_KEYBOARD_INTERACTIVE,
    VIR_NET_LIBSSH_AUTH_PASSWORD,
    VIR_NET_LIBSSH_AUTH_PRIVKEY,
    VIR_NET_LIBSSH_AUTH_AGENT
} virNetLibsshAuthMethods;


typedef struct _virNetLibsshAuthMethod virNetLibsshAuthMethod;
typedef virNetLibsshAuthMethod *virNetLibsshAuthMethodPtr;

struct _virNetLibsshAuthMethod {
    virNetLibsshAuthMethods method;
    int ssh_flags;  /* SSH_AUTH_METHOD_* for this auth method */

    char *password;
    char *filename;

    int tries;
};

struct _virNetLibsshSession {
    virObjectLockable parent;
    virNetLibsshSessionState state;

    /* libssh internal stuff */
    ssh_session session;
    ssh_channel channel;

    /* for host key checking */
    virNetLibsshHostkeyVerify hostKeyVerify;
    char *knownHostsFile;
    char *hostname;
    int port;

    /* authentication stuff */
    char *username;
    virConnectAuthPtr cred;
    char *authPath;
    size_t nauths;
    virNetLibsshAuthMethodPtr *auths;

    /* channel stuff */
    char *channelCommand;
    int channelCommandReturnValue;

    /* read cache */
    char rbuf[VIR_NET_LIBSSH_BUFFER_SIZE];
    size_t bufUsed;
    size_t bufStart;
};

static void
virNetLibsshSessionAuthMethodsFree(virNetLibsshSessionPtr sess)
{
    size_t i;

    for (i = 0; i < sess->nauths; i++) {
        VIR_DISPOSE_STRING(sess->auths[i]->password);
        VIR_FREE(sess->auths[i]->filename);
        VIR_FREE(sess->auths[i]);
    }

    VIR_FREE(sess->auths);
    sess->nauths = 0;
}

static void
virNetLibsshSessionDispose(void *obj)
{
    virNetLibsshSessionPtr sess = obj;
    VIR_DEBUG("sess=0x%p", sess);

    if (!sess)
        return;

    if (sess->channel) {
        ssh_channel_send_eof(sess->channel);
        ssh_channel_close(sess->channel);
        ssh_channel_free(sess->channel);
    }

    if (sess->session) {
        ssh_disconnect(sess->session);
        ssh_free(sess->session);
    }

    virNetLibsshSessionAuthMethodsFree(sess);

    VIR_FREE(sess->channelCommand);
    VIR_FREE(sess->hostname);
    VIR_FREE(sess->knownHostsFile);
    VIR_FREE(sess->authPath);
    VIR_FREE(sess->username);
}

static virClassPtr virNetLibsshSessionClass;
static int
virNetLibsshSessionOnceInit(void)
{
    const char *dbgLevelStr;
    int dbgLevel;

    if (!VIR_CLASS_NEW(virNetLibsshSession, virClassForObjectLockable()))
        return -1;

    if (ssh_init() < 0) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("failed to initialize libssh"));
        return -1;
    }

#if TRACE_LIBSSH != 0
    ssh_set_log_level(TRACE_LIBSSH);
#endif

    dbgLevelStr = getenv("LIBVIRT_LIBSSH_DEBUG");
    if (dbgLevelStr &&
        virStrToLong_i(dbgLevelStr, NULL, 10, &dbgLevel) >= 0)
        ssh_set_log_level(dbgLevel);

    return 0;
}
VIR_ONCE_GLOBAL_INIT(virNetLibsshSession);

static virNetLibsshAuthMethodPtr
virNetLibsshSessionAuthMethodNew(virNetLibsshSessionPtr sess)
{
    virNetLibsshAuthMethodPtr auth;

    if (VIR_ALLOC(auth) < 0)
        goto error;

    if (VIR_EXPAND_N(sess->auths, sess->nauths, 1) < 0)
        goto error;

    sess->auths[sess->nauths - 1] = auth;

    return auth;

 error:
    VIR_FREE(auth);
    return NULL;
}

/* string representation of public key of remote server */
static char *
virLibsshServerKeyAsString(virNetLibsshSessionPtr sess)
{
    int ret;
    ssh_key key;
    unsigned char *keyhash;
    size_t keyhashlen;
    char *str;

    if (ssh_get_server_publickey(sess->session, &key) != SSH_OK) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("failed to get the key of the current "
                         "session"));
        return NULL;
    }

    /* calculate remote key hash, using SHA1 algorithm that is
     * usual in OpenSSH. The returned value must be freed */
    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA1,
                                 &keyhash, &keyhashlen);
    ssh_key_free(key);
    if (ret < 0) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("failed to calculate ssh host key hash"));
        return NULL;
    }
    /* format the host key into a nice userfriendly string. */
    str = ssh_get_hexa(keyhash, keyhashlen);
    ssh_clean_pubkey_hash(&keyhash);

    return str;
}

static int
virCredTypeForPrompt(virConnectAuthPtr cred, char echo)
{
    size_t i;

    for (i = 0; i < cred->ncredtype; ++i) {
        int type = cred->credtype[i];
        if (echo) {
            if (type == VIR_CRED_ECHOPROMPT)
                return type;
        } else {
            if (type == VIR_CRED_PASSPHRASE ||
                type == VIR_CRED_NOECHOPROMPT) {
                return type;
            }
        }
    }

    return -1;
}

static int
virLengthForPromptString(const char *str)
{
    int len = strlen(str);

    while (len > 0 && (str[len-1] == ' ' || str[len-1] == ':'))
        --len;

    return len;
}

/* check session host keys
 *
 * this function checks the known host database and verifies the key
 * errors are raised in this func
 *
 * return value: 0 on success, -1 on error
 */
static int
virNetLibsshCheckHostKey(virNetLibsshSessionPtr sess)
{
    int state;
    char *keyhashstr;
    const char *errmsg;

    if (sess->hostKeyVerify == VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE)
        return 0;

    state = ssh_session_is_known_server(sess->session);

    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        /* host key matches */
        return 0;

    case SSH_SERVER_FOUND_OTHER:
    case SSH_SERVER_KNOWN_CHANGED:
        keyhashstr = virLibsshServerKeyAsString(sess);
        if (!keyhashstr)
            return -1;

        /* host key verification failed */
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("!!! SSH HOST KEY VERIFICATION FAILED !!!: "
                         "Identity of host '%s:%d' differs from stored identity. "
                         "Please verify the new host key '%s' to avoid possible "
                         "man in the middle attack. The key is stored in '%s'."),
                       sess->hostname, sess->port,
                       keyhashstr, sess->knownHostsFile);

        ssh_string_free_char(keyhashstr);
        return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
    case SSH_SERVER_NOT_KNOWN:
        /* key was not found, query to add it to database */
        if (sess->hostKeyVerify == VIR_NET_LIBSSH_HOSTKEY_VERIFY_NORMAL) {
            virConnectCredential askKey;
            int cred_type;
            char *tmp;

            /* ask to add the key */
            if (!sess->cred || !sess->cred->cb) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("No user interaction callback provided: "
                                 "Can't verify the session host key"));
                return -1;
            }

            cred_type = virCredTypeForPrompt(sess->cred, 1 /* echo */);
            if (cred_type == -1) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("no suitable callback for host key "
                                 "verification"));
                return -1;
            }

            /* prepare data for the callback */
            memset(&askKey, 0, sizeof(virConnectCredential));
            askKey.type = cred_type;

            keyhashstr = virLibsshServerKeyAsString(sess);
            if (!keyhashstr)
                return -1;

            if (virAsprintf(&tmp,
                            _("Accept SSH host key with hash '%s' for "
                              "host '%s:%d' (%s/%s)?"),
                            keyhashstr,
                            sess->hostname, sess->port,
                            "y", "n") < 0) {
                ssh_string_free_char(keyhashstr);
                return -1;
            }
            askKey.prompt = tmp;

            if (sess->cred->cb(&askKey, 1, sess->cred->cbdata)) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("failed to retrieve decision to accept "
                                 "host key"));
                VIR_FREE(tmp);
                ssh_string_free_char(keyhashstr);
                return -1;
            }

            VIR_FREE(tmp);

            if (!askKey.result ||
                STRCASENEQ(askKey.result, "y")) {
                virReportError(VIR_ERR_LIBSSH,
                               _("SSH host key for '%s' (%s) was not accepted"),
                               sess->hostname, keyhashstr);
                ssh_string_free_char(keyhashstr);
                VIR_FREE(askKey.result);
                return -1;
            }
            ssh_string_free_char(keyhashstr);
            VIR_FREE(askKey.result);
        }

        /* write the host key file, if specified */
        if (sess->knownHostsFile) {
            if (ssh_session_update_known_hosts(sess->session) < 0) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_LIBSSH,
                               _("failed to write known_host file '%s': %s"),
                               sess->knownHostsFile,
                               errmsg);
                return -1;
            }
        }
        /* key was accepted and added */
        return 0;

    case SSH_SERVER_ERROR:
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to validate SSH host key: %s"),
                       errmsg);
        return -1;

    default: /* should never happen (tm) */
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Unknown state of the remote server SSH key"));
        return -1;
    }

    return -1;
}

/* callback for ssh_pki_import_privkey_file, used to get the passphrase
 * of a private key
 */
static int
virNetLibsshAuthenticatePrivkeyCb(const char *prompt,
                                  char *buf,
                                  size_t len,
                                  int echo,
                                  int verify ATTRIBUTE_UNUSED,
                                  void *userdata)
{
    virNetLibsshSessionPtr sess = userdata;
    virConnectCredential retr_passphrase;
    int cred_type;
    char *actual_prompt = NULL;
    int p;

    /* request user's key password */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No user interaction callback provided: "
                         "Can't retrieve private key passphrase"));
        return -1;
    }

    cred_type = virCredTypeForPrompt(sess->cred, echo);
    if (cred_type == -1) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("no suitable callback for input of key passphrase"));
        goto error;
    }

    if (VIR_STRNDUP(actual_prompt, prompt,
                    virLengthForPromptString(prompt)) < 0)
        goto error;

    memset(&retr_passphrase, 0, sizeof(virConnectCredential));
    retr_passphrase.type = cred_type;
    retr_passphrase.prompt = actual_prompt;

    if (sess->cred->cb(&retr_passphrase, 1, sess->cred->cbdata)) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("failed to retrieve private key passphrase: "
                         "callback has failed"));
        goto error;
    }

    p = virStrncpy(buf, retr_passphrase.result,
                   retr_passphrase.resultlen, len);
    VIR_DISPOSE_STRING(retr_passphrase.result);
    if (p < 0) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("passphrase is too long for the buffer"));
        goto error;
    }

    VIR_FREE(actual_prompt);

    return 0;

 error:
    VIR_FREE(actual_prompt);
    return -1;
}

static int
virNetLibsshImportPrivkey(virNetLibsshSessionPtr sess,
                          virNetLibsshAuthMethodPtr priv,
                          ssh_key *ret_key)
{
    int err;
    int ret;
    ssh_key key;

    /* try open the key with the password set, first; since it can
     * fail with SSH_ERROR also without the callback being called,
     * reset the error so it is possible to check whether the callback
     * failed or libssh did.
     */
    virResetLastError();
    ret = ssh_pki_import_privkey_file(priv->filename, priv->password,
                                      virNetLibsshAuthenticatePrivkeyCb,
                                      sess, &key);
    if (ret == SSH_EOF) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("error while reading private key '%s'"),
                       priv->filename);
        err = SSH_AUTH_ERROR;
        goto error;
    } else if (ret == SSH_ERROR) {
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("error while opening private key '%s', wrong "
                             "passphrase?"),
                           priv->filename);
        }
        err = SSH_AUTH_ERROR;
        goto error;
    }

    *ret_key = key;
    return SSH_AUTH_SUCCESS;

 error:
    return err;
}


/* perform private key authentication
 *
 * returns SSH_AUTH_* values
 */
static int
virNetLibsshAuthenticatePrivkey(virNetLibsshSessionPtr sess,
                                virNetLibsshAuthMethodPtr priv)
{
    int err;
    int ret;
    char *tmp = NULL;
    ssh_key public_key = NULL;
    ssh_key private_key = NULL;

    VIR_DEBUG("sess=%p", sess);

    if (virAsprintf(&tmp, "%s.pub", priv->filename) < 0) {
        err = SSH_AUTH_ERROR;
        goto error;
    }

    /* try to open the public part of the private key */
    ret = ssh_pki_import_pubkey_file(tmp, &public_key);
    if (ret == SSH_ERROR) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("error while reading public key '%s'"),
                       tmp);
        err = SSH_AUTH_ERROR;
        goto error;
    } else if (ret == SSH_EOF) {
        /* load the private key */
        err = virNetLibsshImportPrivkey(sess, priv, &private_key);
        if (err != SSH_AUTH_SUCCESS)
            goto error;

        /* create the public key from the private key */
        ret = ssh_pki_export_privkey_to_pubkey(private_key, &public_key);
        if (ret == SSH_ERROR) {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("cannot export the public key from the "
                             "private key '%s'"),
                           priv->filename);
            err = SSH_AUTH_ERROR;
            goto error;
        }
    }

    VIR_FREE(tmp);

    ret = ssh_userauth_try_publickey(sess->session, NULL, public_key);
    if (ret != SSH_AUTH_SUCCESS) {
        err = SSH_AUTH_DENIED;
        goto error;
    }

    /* load the private key, if it was not loaded yet */
    if (private_key == NULL) {
        err = virNetLibsshImportPrivkey(sess, priv, &private_key);
        if (err != SSH_AUTH_SUCCESS)
            goto error;
    }

    ret = ssh_userauth_publickey(sess->session, NULL, private_key);
    if (ret != SSH_AUTH_SUCCESS) {
        err = SSH_AUTH_DENIED;
        goto error;
    }

    ssh_key_free(private_key);
    ssh_key_free(public_key);

    return SSH_AUTH_SUCCESS;

 error:
    if (private_key)
        ssh_key_free(private_key);
    if (public_key)
        ssh_key_free(public_key);
    VIR_FREE(tmp);
    return err;
}


/* perform password authentication, either directly or request the password
 *
 * returns SSH_AUTH_* values
 */
static int
virNetLibsshAuthenticatePassword(virNetLibsshSessionPtr sess,
                                 virNetLibsshAuthMethodPtr priv)
{
    const char *errmsg;
    int rc = SSH_AUTH_ERROR;

    VIR_DEBUG("sess=%p", sess);

    if (priv->password) {
        /* tunelled password authentication */
        if ((rc = ssh_userauth_password(sess->session, NULL,
                                        priv->password)) == 0)
            return SSH_AUTH_SUCCESS;
    } else {
        /* password authentication with interactive password request */
        if (!sess->cred || !sess->cred->cb) {
            virReportError(VIR_ERR_LIBSSH, "%s",
                           _("Can't perform authentication: "
                             "Authentication callback not provided"));
            return SSH_AUTH_ERROR;
        }

        /* Try the authenticating the set amount of times. The server breaks the
         * connection if maximum number of bad auth tries is exceeded */
        while (true) {
            VIR_AUTODISPOSE_STR password = NULL;

            if (!(password = virAuthGetPasswordPath(sess->authPath, sess->cred,
                                                    "ssh", sess->username,
                                                    sess->hostname)))
                return SSH_AUTH_ERROR;

            /* tunelled password authentication */
            if ((rc = ssh_userauth_password(sess->session, NULL,
                                            password)) == 0)
                return SSH_AUTH_SUCCESS;

            if (rc != SSH_AUTH_DENIED)
                break;
        }
    }

    /* error path */
    errmsg = ssh_get_error(sess->session);
    virReportError(VIR_ERR_AUTH_FAILED,
                   _("authentication failed: %s"), errmsg);
    return rc;
}

/* perform keyboard interactive authentication
 *
 * returns SSH_AUTH_* values
 */
static int
virNetLibsshAuthenticateKeyboardInteractive(virNetLibsshSessionPtr sess,
                                            virNetLibsshAuthMethodPtr priv)
{
    int ret;
    const char *errmsg;
    int try = 0;

    /* request user's key password */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No user interaction callback provided: "
                         "Can't get input from keyboard interactive "
                         "authentication"));
        return SSH_AUTH_ERROR;
    }

 again:
    ret = ssh_userauth_kbdint(sess->session, NULL, NULL);
    while (ret == SSH_AUTH_INFO) {
        const char *name, *instruction;
        int nprompts, iprompt;
        virBuffer buff = VIR_BUFFER_INITIALIZER;

        name = ssh_userauth_kbdint_getname(sess->session);
        instruction = ssh_userauth_kbdint_getinstruction(sess->session);
        nprompts = ssh_userauth_kbdint_getnprompts(sess->session);

        /* compose the main buffer with name and instruction, if present */
        if (name && name[0])
            virBufferAddStr(&buff, name);
        if (instruction && instruction[0]) {
            if (virBufferUse(&buff) > 0)
                virBufferAddChar(&buff, '\n');
            virBufferAddStr(&buff, instruction);
        }
        if (virBufferUse(&buff) > 0)
            virBufferAddChar(&buff, '\n');

        if (virBufferCheckError(&buff) < 0)
            return -1;

        for (iprompt = 0; iprompt < nprompts; ++iprompt) {
            virConnectCredential retr_passphrase;
            const char *promptStr;
            int promptStrLen;
            char echo;
            char *prompt = NULL;
            int cred_type;

            /* get the prompt */
            promptStr = ssh_userauth_kbdint_getprompt(sess->session, iprompt,
                                                      &echo);
            promptStrLen = virLengthForPromptString(promptStr);

            cred_type = virCredTypeForPrompt(sess->cred, echo);
            if (cred_type == -1) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("no suitable callback for input of keyboard "
                                 "response"));
                goto prompt_error;
            }

            /* create the prompt for the user, using the instruction
             * buffer if specified
             */
            if (virBufferUse(&buff) > 0) {
                virBuffer prompt_buff = VIR_BUFFER_INITIALIZER;

                virBufferAddBuffer(&prompt_buff, &buff);
                virBufferAdd(&prompt_buff, promptStr, promptStrLen);

                if (virBufferCheckError(&prompt_buff) < 0)
                    goto prompt_error;

                prompt = virBufferContentAndReset(&prompt_buff);
            } else {
                if (VIR_STRNDUP(prompt, promptStr, promptStrLen) < 0)
                    goto prompt_error;
            }

            memset(&retr_passphrase, 0, sizeof(virConnectCredential));
            retr_passphrase.type = cred_type;
            retr_passphrase.prompt = prompt;

            if (retr_passphrase.type == -1) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("no suitable callback for input of key "
                                 "passphrase"));
                goto prompt_error;
            }

            if (sess->cred->cb(&retr_passphrase, 1, sess->cred->cbdata)) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("failed to retrieve keyboard interactive "
                                 "result: callback has failed"));
                goto prompt_error;
            }

            VIR_FREE(prompt);

            ret = ssh_userauth_kbdint_setanswer(sess->session, iprompt,
                                                retr_passphrase.result);
            VIR_DISPOSE_STRING(retr_passphrase.result);
            if (ret < 0) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_AUTH_FAILED,
                               _("authentication failed: %s"), errmsg);
                goto prompt_error;
            }

            continue;

         prompt_error:
            VIR_FREE(prompt);
            virBufferFreeAndReset(&buff);
            return SSH_AUTH_ERROR;
        }

        virBufferFreeAndReset(&buff);

        ret = ssh_userauth_kbdint(sess->session, NULL, NULL);
        ++try;
        if (ret == SSH_AUTH_DENIED && (priv->tries < 0 || try < priv->tries))
            goto again;
    }

    if (ret == SSH_AUTH_ERROR) {
        /* error path */
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("authentication failed: %s"), errmsg);
    }

    return ret;
}

/* select auth method and authenticate */
static int
virNetLibsshAuthenticate(virNetLibsshSessionPtr sess)
{
    virNetLibsshAuthMethodPtr auth;
    bool no_method = false;
    bool auth_failed = false;
    const char *errmsg;
    int ret;
    int methods;
    size_t i;

    VIR_DEBUG("sess=%p", sess);

    /* At this point, we can assume there is at least one
     * authentication method set -- virNetLibsshValidateConfig
     * already checked that.
     */

    /* try to authenticate */
    ret = ssh_userauth_none(sess->session, NULL);
    if (ret == SSH_AUTH_ERROR) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("Failed to authenticate as 'none': %s"),
                       errmsg);
        return -1;
    }

    /* obtain list of supported auth methods */
    methods = ssh_userauth_list(sess->session, NULL);

    for (i = 0; i < sess->nauths; i++) {
        auth = sess->auths[i];

        if ((methods & auth->ssh_flags) == 0) {
            no_method = true;
            continue;
        }

        ret = SSH_AUTH_DENIED;

        switch (auth->method) {
        case VIR_NET_LIBSSH_AUTH_KEYBOARD_INTERACTIVE:
            /* try to authenticate using the keyboard interactive way */
            ret = virNetLibsshAuthenticateKeyboardInteractive(sess, auth);
            break;
        case VIR_NET_LIBSSH_AUTH_AGENT:
            /* try to authenticate using ssh-agent */
            ret = ssh_userauth_agent(sess->session, NULL);
            if (ret == SSH_AUTH_ERROR) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_LIBSSH,
                               _("failed to authenticate using agent: %s"),
                               errmsg);
            }
            break;
        case VIR_NET_LIBSSH_AUTH_PRIVKEY:
            /* try to authenticate using the provided ssh key */
            ret = virNetLibsshAuthenticatePrivkey(sess, auth);
            break;
        case VIR_NET_LIBSSH_AUTH_PASSWORD:
            /* try to authenticate with password */
            ret = virNetLibsshAuthenticatePassword(sess, auth);
            break;
        }

        if (ret == SSH_AUTH_ERROR) {
            /* virReportError is called already */
            return -1;
        } else if (ret == SSH_AUTH_SUCCESS) {
            /* authenticated */
            return 0;
        }

        auth_failed = true;
    }

    if (sess->nauths == 1) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to authenticate: %s"),
                       errmsg);
    } else if (no_method && !auth_failed) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("None of the requested authentication methods "
                         "are supported by the server"));
    } else {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("All provided authentication methods with credentials "
                         "were rejected by the server"));
    }

    return -1;
}

/* open channel */
static int
virNetLibsshOpenChannel(virNetLibsshSessionPtr sess)
{
    const char *errmsg;

    sess->channel = ssh_channel_new(sess->session);
    if (!sess->channel) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to create libssh channel: %s"),
                       errmsg);
        return -1;
    }

    if (ssh_channel_open_session(sess->channel) != SSH_OK) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to open ssh channel: %s"),
                       errmsg);
        return -1;
    }

    if (ssh_channel_request_exec(sess->channel, sess->channelCommand) != SSH_OK) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to execute command '%s': %s"),
                       sess->channelCommand,
                       errmsg);
        return -1;
    }

    /* nonblocking mode */
    ssh_channel_set_blocking(sess->channel, 0);

    /* channel open */
    return 0;
}

/* validate if all required parameters are configured */
static int
virNetLibsshValidateConfig(virNetLibsshSessionPtr sess)
{
    size_t i;
    bool has_auths = false;

    for (i = 0; i < sess->nauths; ++i) {
        if (sess->auths[i]) {
            has_auths = true;
            break;
        }
    }
    if (!has_auths) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No authentication methods and credentials "
                         "provided"));
        return -1;
    }

    if (!sess->channelCommand) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No channel command provided"));
        return -1;
    }

    if (sess->hostKeyVerify != VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE) {
        if (!sess->hostname) {
            virReportError(VIR_ERR_LIBSSH, "%s",
                           _("Hostname is needed for host key verification"));
            return -1;
        }
    }

    /* everything ok */
    return 0;
}

/* ### PUBLIC API ### */
int
virNetLibsshSessionAuthSetCallback(virNetLibsshSessionPtr sess,
                                   virConnectAuthPtr auth)
{
    virObjectLock(sess);
    sess->cred = auth;
    virObjectUnlock(sess);
    return 0;
}

int
virNetLibsshSessionAuthAddPasswordAuth(virNetLibsshSessionPtr sess,
                                       virURIPtr uri)
{
    int ret;
    virNetLibsshAuthMethodPtr auth;

    if (uri) {
        VIR_FREE(sess->authPath);

        if (virAuthGetConfigFilePathURI(uri, &sess->authPath) < 0) {
            ret = -1;
            goto cleanup;
        }
    }

    virObjectLock(sess);

    if (!(auth = virNetLibsshSessionAuthMethodNew(sess))) {
        ret = -1;
        goto cleanup;
    }

    auth->method = VIR_NET_LIBSSH_AUTH_PASSWORD;
    auth->ssh_flags = SSH_AUTH_METHOD_PASSWORD;

    ret = 0;

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

int
virNetLibsshSessionAuthAddAgentAuth(virNetLibsshSessionPtr sess)
{
    int ret;
    virNetLibsshAuthMethodPtr auth;

    virObjectLock(sess);

    if (!(auth = virNetLibsshSessionAuthMethodNew(sess))) {
        ret = -1;
        goto cleanup;
    }

    auth->method = VIR_NET_LIBSSH_AUTH_AGENT;
    auth->ssh_flags = SSH_AUTH_METHOD_PUBLICKEY;

    ret = 0;

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

int
virNetLibsshSessionAuthAddPrivKeyAuth(virNetLibsshSessionPtr sess,
                                      const char *keyfile,
                                      const char *password)
{
    int ret;
    virNetLibsshAuthMethodPtr auth;
    VIR_AUTODISPOSE_STR pass = NULL;
    char *file = NULL;

    if (!keyfile) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Key file path must be provided "
                         "for private key authentication"));
        ret = -1;
        goto error;
    }

    virObjectLock(sess);

    if (VIR_STRDUP(file, keyfile) < 0 ||
        VIR_STRDUP(pass, password) < 0) {
        ret = -1;
        goto error;
    }

    if (!(auth = virNetLibsshSessionAuthMethodNew(sess))) {
        ret = -1;
        goto error;
    }

    VIR_STEAL_PTR(auth->password, pass);
    auth->filename = file;
    auth->method = VIR_NET_LIBSSH_AUTH_PRIVKEY;
    auth->ssh_flags = SSH_AUTH_METHOD_PUBLICKEY;

    ret = 0;

 cleanup:
    virObjectUnlock(sess);
    return ret;

 error:
    VIR_FREE(file);
    goto cleanup;
}

int
virNetLibsshSessionAuthAddKeyboardAuth(virNetLibsshSessionPtr sess,
                                       int tries)
{
    int ret;
    virNetLibsshAuthMethodPtr auth;

    virObjectLock(sess);

    if (!(auth = virNetLibsshSessionAuthMethodNew(sess))) {
        ret = -1;
        goto cleanup;
    }

    auth->tries = tries;
    auth->method = VIR_NET_LIBSSH_AUTH_KEYBOARD_INTERACTIVE;
    auth->ssh_flags = SSH_AUTH_METHOD_INTERACTIVE;

    ret = 0;

 cleanup:
    virObjectUnlock(sess);
    return ret;

}

int
virNetLibsshSessionSetChannelCommand(virNetLibsshSessionPtr sess,
                                      const char *command)
{
    int ret = 0;
    virObjectLock(sess);

    VIR_FREE(sess->channelCommand);

    if (VIR_STRDUP(sess->channelCommand, command) < 0)
        ret = -1;

    virObjectUnlock(sess);
    return ret;
}

int
virNetLibsshSessionSetHostKeyVerification(virNetLibsshSessionPtr sess,
                                          const char *hostname,
                                          int port,
                                          const char *hostsfile,
                                          virNetLibsshHostkeyVerify opt)
{
    virObjectLock(sess);

    sess->port = port;
    sess->hostKeyVerify = opt;

    VIR_FREE(sess->hostname);

    if (VIR_STRDUP(sess->hostname, hostname) < 0)
        goto error;

    /* set the hostname */
    if (ssh_options_set(sess->session, SSH_OPTIONS_HOST, sess->hostname) < 0)
        goto error;

    /* set the port */
    if (port > 0) {
        unsigned int portU = port;

        if (ssh_options_set(sess->session, SSH_OPTIONS_PORT, &portU) < 0)
            goto error;
    }

    /* set the known hosts file, if specified */
    if (hostsfile) {
        if (ssh_options_set(sess->session, SSH_OPTIONS_KNOWNHOSTS, hostsfile) < 0)
            goto error;

        VIR_FREE(sess->knownHostsFile);
        if (VIR_STRDUP(sess->knownHostsFile, hostsfile) < 0)
            goto error;
    } else {
        /* libssh does not support trying no known_host file at all:
         * hence use /dev/null here, without storing it as file */
        if (ssh_options_set(sess->session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null") < 0)
            goto error;
    }

    virObjectUnlock(sess);
    return 0;

 error:
    virObjectUnlock(sess);
    return -1;
}

/* allocate and initialize a libssh session object */
virNetLibsshSessionPtr virNetLibsshSessionNew(const char *username)
{
    virNetLibsshSessionPtr sess = NULL;

    if (virNetLibsshSessionInitialize() < 0)
        goto error;

    if (!(sess = virObjectLockableNew(virNetLibsshSessionClass)))
        goto error;

    /* initialize session data */
    if (!(sess->session = ssh_new())) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Failed to initialize libssh session"));
        goto error;
    }

    if (VIR_STRDUP(sess->username, username) < 0)
        goto error;

    VIR_DEBUG("virNetLibsshSessionPtr: %p, ssh_session: %p",
              sess, sess->session);

    /* set blocking mode for libssh until handshake is complete */
    ssh_set_blocking(sess->session, 1);

    if (ssh_options_set(sess->session, SSH_OPTIONS_USER, sess->username) < 0)
        goto error;

    /* default states for config variables */
    sess->state = VIR_NET_LIBSSH_STATE_NEW;
    sess->hostKeyVerify = VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE;

    return sess;

 error:
    virObjectUnref(sess);
    return NULL;
}

int
virNetLibsshSessionConnect(virNetLibsshSessionPtr sess,
                           int sock)
{
    int ret;
    const char *errmsg;

    VIR_DEBUG("sess=%p, sock=%d", sess, sock);

    if (!sess || sess->state != VIR_NET_LIBSSH_STATE_NEW) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Invalid virNetLibsshSessionPtr"));
        return -1;
    }

    virObjectLock(sess);

    /* check if configuration is valid */
    if ((ret = virNetLibsshValidateConfig(sess)) < 0)
        goto error;

    /* read ~/.ssh/config */
    if ((ret = ssh_options_parse_config(sess->session, NULL)) < 0)
        goto error;

    /* set the socket FD for the libssh session */
    if ((ret = ssh_options_set(sess->session, SSH_OPTIONS_FD, &sock)) < 0)
        goto error;

    /* open session */
    ret = ssh_connect(sess->session);
    /* libssh is in blocking mode, so EAGAIN will never happen */
    if (ret < 0) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_NO_CONNECT,
                       _("SSH session handshake failed: %s"),
                       errmsg);
        goto error;
    }

    /* verify the SSH host key */
    if ((ret = virNetLibsshCheckHostKey(sess)) != 0)
        goto error;

    /* authenticate */
    if ((ret = virNetLibsshAuthenticate(sess)) != 0)
        goto error;

    /* open channel */
    if ((ret = virNetLibsshOpenChannel(sess)) != 0)
        goto error;

    /* all set */
    /* switch to nonblocking mode and return */
    ssh_set_blocking(sess->session, 0);
    sess->state = VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE;

    virObjectUnlock(sess);
    return ret;

 error:
    sess->state = VIR_NET_LIBSSH_STATE_ERROR;
    virObjectUnlock(sess);
    return ret;
}

/* do a read from a ssh channel, used instead of normal read on socket */
ssize_t
virNetLibsshChannelRead(virNetLibsshSessionPtr sess,
                        char *buf,
                        size_t len)
{
    int ret = -1;
    ssize_t read_n = 0;

    virObjectLock(sess);

    if (sess->state != VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_LIBSSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote program terminated "
                             "with non-zero code: %d"),
                           sess->channelCommandReturnValue);
        else
            virReportError(VIR_ERR_LIBSSH, "%s",
                           _("Tried to write socket in error state"));

        virObjectUnlock(sess);
        return -1;
    }

    if (sess->bufUsed > 0) {
        /* copy the rest (or complete) internal buffer to the output buffer */
        memcpy(buf,
               sess->rbuf + sess->bufStart,
               len > sess->bufUsed ? sess->bufUsed : len);

        if (len >= sess->bufUsed) {
            read_n = sess->bufUsed;

            sess->bufStart = 0;
            sess->bufUsed = 0;
        } else {
            read_n = len;
            sess->bufUsed -= len;
            sess->bufStart += len;

            goto success;
        }
    }

    /* continue reading into the buffer supplied */
    if (read_n < len) {
        ret = ssh_channel_read_nonblocking(sess->channel,
                                           buf + read_n,
                                           len - read_n,
                                           0);

        if (ret == SSH_EOF || (ret == 0 && ssh_channel_is_eof(sess->channel)))
            goto eof;

        if (ret == SSH_AGAIN)
            goto success;

        if (ret < 0)
            goto error;

        read_n += ret;
    }

    /* try to read something into the internal buffer */
    if (sess->bufUsed == 0) {
        ret = ssh_channel_read_nonblocking(sess->channel,
                                           sess->rbuf,
                                           VIR_NET_LIBSSH_BUFFER_SIZE,
                                           0);

        if (ret == SSH_EOF || (ret == 0 && ssh_channel_is_eof(sess->channel)))
            goto eof;

        if (ret == SSH_AGAIN)
            goto success;

        if (ret < 0)
            goto error;

        sess->bufUsed = ret;
        sess->bufStart = 0;
    }

    if (read_n == 0) {
        /* get rid of data in stderr stream */
        ret = ssh_channel_read_nonblocking(sess->channel,
                                           sess->rbuf,
                                           VIR_NET_LIBSSH_BUFFER_SIZE - 1,
                                           1);
        if (ret > 0) {
            sess->rbuf[ret] = '\0';
            VIR_DEBUG("flushing stderr, data='%s'",  sess->rbuf);
        }
    }

    if (ssh_channel_is_eof(sess->channel)) {
 eof:
        if (ssh_channel_get_exit_status(sess->channel)) {
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote command terminated with non-zero code: %d"),
                           ssh_channel_get_exit_status(sess->channel));
            sess->channelCommandReturnValue = ssh_channel_get_exit_status(sess->channel);
            sess->state = VIR_NET_LIBSSH_STATE_ERROR_REMOTE;
            virObjectUnlock(sess);
            return -1;
        }

        sess->state = VIR_NET_LIBSSH_STATE_CLOSED;
        virObjectUnlock(sess);
        return -1;
    }

 success:
    virObjectUnlock(sess);
    return read_n;

 error:
    sess->state = VIR_NET_LIBSSH_STATE_ERROR;
    virObjectUnlock(sess);
    return ret;
}

ssize_t
virNetLibsshChannelWrite(virNetLibsshSessionPtr sess,
                         const char *buf,
                         size_t len)
{
    ssize_t ret;

    virObjectLock(sess);

    if (sess->state != VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_LIBSSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote program terminated with non-zero code: %d"),
                           sess->channelCommandReturnValue);
        else
            virReportError(VIR_ERR_LIBSSH, "%s",
                           _("Tried to write socket in error state"));
        ret = -1;
        goto cleanup;
    }

    if (ssh_channel_is_eof(sess->channel)) {
        if (ssh_channel_get_exit_status(sess->channel)) {
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote program terminated with non-zero code: %d"),
                           ssh_channel_get_exit_status(sess->channel));
            sess->state = VIR_NET_LIBSSH_STATE_ERROR_REMOTE;
            sess->channelCommandReturnValue = ssh_channel_get_exit_status(sess->channel);

            ret = -1;
            goto cleanup;
        }

        sess->state = VIR_NET_LIBSSH_STATE_CLOSED;
        ret = -1;
        goto cleanup;
    }

    ret = ssh_channel_write(sess->channel, buf, len);
    if (ret == SSH_AGAIN) {
        ret = 0;
        goto cleanup;
    }

    if (ret < 0) {
        const char *msg;
        sess->state = VIR_NET_LIBSSH_STATE_ERROR;
        msg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("write failed: %s"), msg);
    }

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

bool
virNetLibsshSessionHasCachedData(virNetLibsshSessionPtr sess)
{
    bool ret;

    if (!sess)
        return false;

    virObjectLock(sess);

    ret = sess->bufUsed > 0;

    virObjectUnlock(sess);
    return ret;
}
