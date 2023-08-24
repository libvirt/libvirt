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
#include "virerror.h"
#include "virobject.h"
#include "virstring.h"
#include "virauth.h"
#include "virbuffer.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_LIBSSH

VIR_LOG_INIT("rpc.netlibsshsession");

#define VIR_NET_LIBSSH_BUFFER_SIZE  1024

/* TRACE_LIBSSH=<level> enables tracing in libssh itself.
 * The meaning of <level> is described here:
 * https://api.libssh.org/master/group__libssh__log.html
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
struct _virNetLibsshAuthMethod {
    virNetLibsshAuthMethods method;
    int ssh_flags;  /* SSH_AUTH_METHOD_* for this auth method */

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
    virNetLibsshAuthMethod **auths;

    /* channel stuff */
    char *channelCommand;
    int channelCommandReturnValue;

    /* read cache */
    char rbuf[VIR_NET_LIBSSH_BUFFER_SIZE];
    size_t bufUsed;
    size_t bufStart;
};

static void
virNetLibsshSessionDispose(void *obj)
{
    virNetLibsshSession *sess = obj;
    size_t i;

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

    for (i = 0; i < sess->nauths; i++) {
        g_free(sess->auths[i]->filename);
        g_free(sess->auths[i]);
    }

    g_free(sess->auths);

    g_free(sess->channelCommand);
    g_free(sess->hostname);
    g_free(sess->knownHostsFile);
    g_free(sess->authPath);
    g_free(sess->username);
}

static virClass *virNetLibsshSessionClass;
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

static virNetLibsshAuthMethod *
virNetLibsshSessionAuthMethodNew(virNetLibsshSession *sess)
{
    virNetLibsshAuthMethod *auth;

    auth = g_new0(virNetLibsshAuthMethod, 1);

    VIR_EXPAND_N(sess->auths, sess->nauths, 1);
    sess->auths[sess->nauths - 1] = auth;

    return auth;
}

/* string representation of public key of remote server */
static char *
virLibsshServerKeyAsString(virNetLibsshSession *sess)
{
    int ret;
    ssh_key key;
    unsigned char *keyhash;
    size_t keyhashlen;
    char *str;

    if (ssh_get_server_publickey(sess->session, &key) != SSH_OK) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("failed to get the key of the current session"));
        return NULL;
    }

    /* calculate remote key hash, using SHA256 algorithm that is
     * the default in modern OpenSSH, fallback to SHA1 for older
     * libssh. The returned value must be freed */
    ret = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256,
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
virNetLibsshCheckHostKey(virNetLibsshSession *sess)
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
                       _("!!! SSH HOST KEY VERIFICATION FAILED !!!: Identity of host '%1$s:%2$d' differs from stored identity. Please verify the new host key '%3$s' to avoid possible man in the middle attack. The key is stored in '%4$s'."),
                       sess->hostname, sess->port,
                       keyhashstr, sess->knownHostsFile);

        ssh_string_free_char(keyhashstr);
        return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
    case SSH_SERVER_NOT_KNOWN:
        /* key was not found, query to add it to database */
        if (sess->hostKeyVerify == VIR_NET_LIBSSH_HOSTKEY_VERIFY_NORMAL) {
            g_autoptr(virConnectCredential) cred = NULL;
            g_autofree char *prompt = NULL;

            /* ask to add the key */
            if (!sess->cred || !sess->cred->cb) {
                virReportError(VIR_ERR_LIBSSH, "%s",
                               _("No user interaction callback provided: Can't verify the session host key"));
                return -1;
            }

            keyhashstr = virLibsshServerKeyAsString(sess);
            if (!keyhashstr)
                return -1;

            prompt = g_strdup_printf(_("Accept SSH host key with hash '%1$s' for host '%2$s:%3$d' (%4$s/%5$s)?"),
                                     keyhashstr, sess->hostname, sess->port, "y", "n");

            if (!(cred = virAuthAskCredential(sess->cred, prompt, true))) {
                ssh_string_free_char(keyhashstr);
                return -1;
            }

            if (!cred->result ||
                STRCASENEQ(cred->result, "y")) {
                virReportError(VIR_ERR_LIBSSH,
                               _("SSH host key for '%1$s' (%2$s) was not accepted"),
                               sess->hostname, keyhashstr);
                ssh_string_free_char(keyhashstr);
                return -1;
            }
            ssh_string_free_char(keyhashstr);
        }

        /* write the host key file, if specified */
        if (sess->knownHostsFile) {
            if (ssh_session_update_known_hosts(sess->session) < 0) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_LIBSSH,
                               _("failed to write known_host file '%1$s': %2$s"),
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
                       _("failed to validate SSH host key: %1$s"),
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
                                  int verify G_GNUC_UNUSED,
                                  void *userdata)
{
    virNetLibsshSession *sess = userdata;
    g_autofree char *actual_prompt = NULL;
    g_autoptr(virConnectCredential) cred = NULL;

    /* request user's key password */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No user interaction callback provided: Can't retrieve private key passphrase"));
        return -1;
    }

    actual_prompt = g_strndup(prompt, virLengthForPromptString(prompt));

    if (!(cred = virAuthAskCredential(sess->cred, actual_prompt, echo)))
        return -1;

    if (virStrcpy(buf, cred->result, len) < 0) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("passphrase is too long for the buffer"));
        return -1;
    }

    return 0;
}

static int
virNetLibsshImportPrivkey(virNetLibsshSession *sess,
                          virNetLibsshAuthMethod *priv,
                          ssh_key *ret_key)
{
    int ret;
    ssh_key key;

    /* try open the key with the password set, first; since it can
     * fail with SSH_ERROR also without the callback being called,
     * reset the error so it is possible to check whether the callback
     * failed or libssh did.
     */
    virResetLastError();
    ret = ssh_pki_import_privkey_file(priv->filename, NULL,
                                      virNetLibsshAuthenticatePrivkeyCb,
                                      sess, &key);
    if (ret == SSH_EOF) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("error while reading private key '%1$s'"),
                       priv->filename);
        return SSH_AUTH_ERROR;
    } else if (ret == SSH_ERROR) {
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("error while opening private key '%1$s', wrong passphrase?"),
                           priv->filename);
        }
        return SSH_AUTH_ERROR;
    }

    *ret_key = key;
    return SSH_AUTH_SUCCESS;
}


/* perform private key authentication
 *
 * returns SSH_AUTH_* values
 */
static int
virNetLibsshAuthenticatePrivkey(virNetLibsshSession *sess,
                                virNetLibsshAuthMethod *priv)
{
    int err;
    int ret;
    char *tmp = NULL;
    ssh_key public_key = NULL;
    ssh_key private_key = NULL;

    VIR_DEBUG("sess=%p", sess);

    tmp = g_strdup_printf("%s.pub", priv->filename);

    /* try to open the public part of the private key */
    ret = ssh_pki_import_pubkey_file(tmp, &public_key);
    if (ret == SSH_ERROR) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("error while reading public key '%1$s'"),
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
                           _("cannot export the public key from the private key '%1$s'"),
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
virNetLibsshAuthenticatePassword(virNetLibsshSession *sess)
{
    g_autofree char *password = NULL;
    const char *errmsg;
    int rc = SSH_AUTH_ERROR;

    VIR_DEBUG("sess=%p", sess);

    /* password authentication with interactive password request */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Can't perform authentication: Authentication callback not provided"));
        return SSH_AUTH_ERROR;
    }

    /* first try to get password from config */
    if (virAuthGetCredential("ssh", sess->hostname, "password", sess->authPath,
                             &password) < 0)
        return SSH_AUTH_ERROR;

    if (password) {
        rc = ssh_userauth_password(sess->session, NULL, password);
        virSecureEraseString(password);

        if (rc == 0)
            return SSH_AUTH_SUCCESS;
        else if (rc != SSH_AUTH_DENIED)
            goto error;
    }

    /* Try the authenticating the set amount of times. The server breaks the
     * connection if maximum number of bad auth tries is exceeded */
    while (true) {
        g_autoptr(virConnectCredential) cred = NULL;
        g_autofree char *prompt = NULL;

        prompt = g_strdup_printf(_("Enter %1$s's password for %2$s"),
                                 sess->username, sess->hostname);

        if (!(cred = virAuthAskCredential(sess->cred, prompt, false)))
            return SSH_AUTH_ERROR;

        rc = ssh_userauth_password(sess->session, NULL, cred->result);

        if (rc == 0)
            return SSH_AUTH_SUCCESS;
        else if (rc != SSH_AUTH_DENIED)
            break;
    }

 error:
    errmsg = ssh_get_error(sess->session);
    virReportError(VIR_ERR_AUTH_FAILED,
                   _("authentication failed: %1$s"), errmsg);
    return rc;
}

/* perform keyboard interactive authentication
 *
 * returns SSH_AUTH_* values
 */
static int
virNetLibsshAuthenticateKeyboardInteractive(virNetLibsshSession *sess,
                                            virNetLibsshAuthMethod *priv)
{
    int ret;
    const char *errmsg;
    int try = 0;

    /* request user's key password */
    if (!sess->cred || !sess->cred->cb) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("No user interaction callback provided: Can't get input from keyboard interactive authentication"));
        return SSH_AUTH_ERROR;
    }

 again:
    ret = ssh_userauth_kbdint(sess->session, NULL, NULL);
    while (ret == SSH_AUTH_INFO) {
        const char *name, *instruction;
        int nprompts, iprompt;
        g_auto(virBuffer) buff = VIR_BUFFER_INITIALIZER;

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

        for (iprompt = 0; iprompt < nprompts; ++iprompt) {
            const char *promptStr;
            int promptStrLen;
            char echo;
            g_autofree char *prompt = NULL;
            g_autoptr(virConnectCredential) cred = NULL;

            /* get the prompt */
            promptStr = ssh_userauth_kbdint_getprompt(sess->session, iprompt,
                                                      &echo);
            promptStrLen = virLengthForPromptString(promptStr);

            /* create the prompt for the user, using the instruction
             * buffer if specified
             */
            if (virBufferUse(&buff) > 0) {
                g_auto(virBuffer) prompt_buff = VIR_BUFFER_INITIALIZER;

                virBufferAddBuffer(&prompt_buff, &buff);
                virBufferAdd(&prompt_buff, promptStr, promptStrLen);

                prompt = virBufferContentAndReset(&prompt_buff);
            } else {
                prompt = g_strndup(promptStr, promptStrLen);
            }

            if (!(cred = virAuthAskCredential(sess->cred, prompt, echo)))
                return SSH_AUTH_ERROR;

            if (ssh_userauth_kbdint_setanswer(sess->session, iprompt,
                                              cred->result) < 0) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_AUTH_FAILED,
                               _("authentication failed: %1$s"), errmsg);
                return SSH_AUTH_ERROR;
            }

            continue;
        }

        ret = ssh_userauth_kbdint(sess->session, NULL, NULL);
        ++try;
        if (ret == SSH_AUTH_DENIED && (priv->tries < 0 || try < priv->tries))
            goto again;
    }

    if (ret == SSH_AUTH_ERROR) {
        /* error path */
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("authentication failed: %1$s"), errmsg);
    }

    return ret;
}

/* select auth method and authenticate */
static int
virNetLibsshAuthenticate(virNetLibsshSession *sess)
{
    virNetLibsshAuthMethod *auth;
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
                       _("Failed to authenticate as 'none': %1$s"),
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
#ifndef WIN32
            ret = ssh_userauth_agent(sess->session, NULL);
#endif
            if (ret == SSH_AUTH_ERROR) {
                errmsg = ssh_get_error(sess->session);
                virReportError(VIR_ERR_LIBSSH,
                               _("failed to authenticate using agent: %1$s"),
                               errmsg);
            }
            break;
        case VIR_NET_LIBSSH_AUTH_PRIVKEY:
            /* try to authenticate using the provided ssh key */
            ret = virNetLibsshAuthenticatePrivkey(sess, auth);
            break;
        case VIR_NET_LIBSSH_AUTH_PASSWORD:
            /* try to authenticate with password */
            ret = virNetLibsshAuthenticatePassword(sess);
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
                       _("failed to authenticate: %1$s"),
                       errmsg);
    } else if (no_method && !auth_failed) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("None of the requested authentication methods are supported by the server"));
    } else {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("All provided authentication methods with credentials were rejected by the server"));
    }

    return -1;
}

/* open channel */
static int
virNetLibsshOpenChannel(virNetLibsshSession *sess)
{
    const char *errmsg;

    sess->channel = ssh_channel_new(sess->session);
    if (!sess->channel) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to create libssh channel: %1$s"),
                       errmsg);
        return -1;
    }

    if (ssh_channel_open_session(sess->channel) != SSH_OK) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to open ssh channel: %1$s"),
                       errmsg);
        return -1;
    }

    if (ssh_channel_request_exec(sess->channel, sess->channelCommand) != SSH_OK) {
        errmsg = ssh_get_error(sess->session);
        virReportError(VIR_ERR_LIBSSH,
                       _("failed to execute command '%1$s': %2$s"),
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
virNetLibsshValidateConfig(virNetLibsshSession *sess)
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
                       _("No authentication methods and credentials provided"));
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
virNetLibsshSessionAuthSetCallback(virNetLibsshSession *sess,
                                   virConnectAuthPtr auth)
{
    virObjectLock(sess);
    sess->cred = auth;
    virObjectUnlock(sess);
    return 0;
}

int
virNetLibsshSessionAuthAddPasswordAuth(virNetLibsshSession *sess,
                                       virURI *uri)
{
    virNetLibsshAuthMethod *auth;

    virObjectLock(sess);

    if (uri) {
        VIR_FREE(sess->authPath);

        if (virAuthGetConfigFilePathURI(uri, &sess->authPath) < 0) {
            virObjectUnlock(sess);
            return -1;
        }
    }

    auth = virNetLibsshSessionAuthMethodNew(sess);
    auth->method = VIR_NET_LIBSSH_AUTH_PASSWORD;
    auth->ssh_flags = SSH_AUTH_METHOD_PASSWORD;

    virObjectUnlock(sess);
    return 0;
}

int
virNetLibsshSessionAuthAddAgentAuth(virNetLibsshSession *sess G_GNUC_UNUSED)
{
#ifdef WIN32
    virReportError(VIR_ERR_LIBSSH, "%s",
                   _("Agent authentication is not supported on this host"));
    return -1;
#else
    virNetLibsshAuthMethod *auth;

    virObjectLock(sess);

    auth = virNetLibsshSessionAuthMethodNew(sess);
    auth->method = VIR_NET_LIBSSH_AUTH_AGENT;
    auth->ssh_flags = SSH_AUTH_METHOD_PUBLICKEY;

    virObjectUnlock(sess);
    return 0;
#endif
}

int
virNetLibsshSessionAuthAddPrivKeyAuth(virNetLibsshSession *sess,
                                      const char *keyfile)
{
    virNetLibsshAuthMethod *auth;

    if (!keyfile) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Key file path must be provided for private key authentication"));
        return -1;
    }

    virObjectLock(sess);

    auth = virNetLibsshSessionAuthMethodNew(sess);
    auth->filename = g_strdup(keyfile);
    auth->method = VIR_NET_LIBSSH_AUTH_PRIVKEY;
    auth->ssh_flags = SSH_AUTH_METHOD_PUBLICKEY;

    virObjectUnlock(sess);
    return 0;
}

int
virNetLibsshSessionAuthAddKeyboardAuth(virNetLibsshSession *sess,
                                       int tries)
{
    virNetLibsshAuthMethod *auth;

    virObjectLock(sess);

    auth = virNetLibsshSessionAuthMethodNew(sess);

    auth->tries = tries;
    auth->method = VIR_NET_LIBSSH_AUTH_KEYBOARD_INTERACTIVE;
    auth->ssh_flags = SSH_AUTH_METHOD_INTERACTIVE;

    virObjectUnlock(sess);
    return 0;
}

void
virNetLibsshSessionSetChannelCommand(virNetLibsshSession *sess,
                                      const char *command)
{
    virObjectLock(sess);

    VIR_FREE(sess->channelCommand);

    sess->channelCommand = g_strdup(command);

    virObjectUnlock(sess);
}

int
virNetLibsshSessionSetHostKeyVerification(virNetLibsshSession *sess,
                                          const char *hostname,
                                          int port,
                                          const char *hostsfile,
                                          virNetLibsshHostkeyVerify opt)
{
    virObjectLock(sess);

    sess->port = port;
    sess->hostKeyVerify = opt;

    VIR_FREE(sess->hostname);

    sess->hostname = g_strdup(hostname);

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
        sess->knownHostsFile = g_strdup(hostsfile);
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
virNetLibsshSession *virNetLibsshSessionNew(const char *username)
{
    virNetLibsshSession *sess = NULL;

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

    sess->username = g_strdup(username);

    VIR_DEBUG("virNetLibsshSession *: %p, ssh_session: %p",
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
virNetLibsshSessionConnect(virNetLibsshSession *sess,
                           int sock)
{
    int ret;
    const char *errmsg;

    VIR_DEBUG("sess=%p, sock=%d", sess, sock);

    if (!sess || sess->state != VIR_NET_LIBSSH_STATE_NEW) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Invalid virNetLibsshSession *"));
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
                       _("SSH session handshake failed: %1$s"),
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
virNetLibsshChannelRead(virNetLibsshSession *sess,
                        char *buf,
                        size_t len)
{
    int ret = -1;
    ssize_t read_n = 0;

    virObjectLock(sess);

    if (sess->state != VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_LIBSSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote program terminated with non-zero code: %1$d"),
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
                           _("Remote command terminated with non-zero code: %1$d"),
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
virNetLibsshChannelWrite(virNetLibsshSession *sess,
                         const char *buf,
                         size_t len)
{
    ssize_t ret;

    virObjectLock(sess);

    if (sess->state != VIR_NET_LIBSSH_STATE_HANDSHAKE_COMPLETE) {
        if (sess->state == VIR_NET_LIBSSH_STATE_ERROR_REMOTE)
            virReportError(VIR_ERR_LIBSSH,
                           _("Remote program terminated with non-zero code: %1$d"),
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
                           _("Remote program terminated with non-zero code: %1$d"),
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
                       _("write failed: %1$s"), msg);
    }

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

bool
virNetLibsshSessionHasCachedData(virNetLibsshSession *sess)
{
    bool ret;

    if (!sess)
        return false;

    virObjectLock(sess);

    ret = sess->bufUsed > 0;

    virObjectUnlock(sess);
    return ret;
}
