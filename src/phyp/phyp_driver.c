
/*
 * Copyright IBM Corp. 2009
 *
 * phyp_driver.c: ssh layer to access Power Hypervisors
 *
 * Authors:
 *  Eduardo Otubo <otubo at linux.vnet.ibm.com>
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <libssh2.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <domain_event.h>

#include "internal.h"
#include "util.h"
#include "datatypes.h"
#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "driver.h"
#include "libvirt/libvirt.h"
#include "virterror_internal.h"
#include "uuid.h"
#include "domain_conf.h"
#include "nodeinfo.h"

#include "phyp_driver.h"

#define VIR_FROM_THIS VIR_FROM_PHYP

#define PHYP_ERROR(conn, code, fmt...)                                        \
    virReportErrorHelper(conn, VIR_FROM_PHYP, code, __FILE__, __FUNCTION__,   \
                         __LINE__, fmt)

/*
 * URI: phyp://user@[hmc|ivm]/managed_system
 * */

static virDrvOpenStatus
phypOpen(virConnectPtr conn,
         virConnectAuthPtr auth, int flags ATTRIBUTE_UNUSED)
{
    LIBSSH2_SESSION *session = NULL;
    ConnectionData *connection_data = NULL;
    char *string = NULL;
    size_t len = 0;
    int internal_socket;
    uuid_tablePtr uuid_table = NULL;
    phyp_driverPtr phyp_driver = NULL;
    char *char_ptr;
    char *managed_system;

    if (!conn || !conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->scheme == NULL || STRNEQ(conn->uri->scheme, "phyp"))
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->server == NULL) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing server name in phyp:// URI"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (conn->uri->path == NULL) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing managed system name in phyp:// URI"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (conn->uri->user == NULL) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing username in phyp:// URI"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (VIR_ALLOC(phyp_driver) < 0) {
        virReportOOMError();
        goto failure;
    }

    if (VIR_ALLOC(uuid_table) < 0) {
        virReportOOMError();
        goto failure;
    }

    if (VIR_ALLOC(connection_data) < 0) {
        virReportOOMError();
        goto failure;
    }

    len = strlen(conn->uri->path) + 1;

    if (VIR_ALLOC_N(string, len) < 0) {
        virReportOOMError();
        goto failure;
    }

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (conn->uri->path[0] == '/')
        managed_system = strdup(conn->uri->path + 1);
    else
        managed_system = strdup(conn->uri->path);

    if (!managed_system) {
        virReportOOMError();
        goto failure;
    }

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (escape_specialcharacters(conn->uri->path, string, len) == -1) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Error parsing 'path'. Invalid characters."));
        goto failure;
    }

    if ((session = openSSHSession(conn, auth, &internal_socket)) == NULL) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Error while opening SSH session."));
        goto failure;
    }
    //conn->uri->path = string;
    connection_data->session = session;
    connection_data->auth = auth;

    uuid_table->nlpars = 0;
    uuid_table->lpars = NULL;

    phyp_driver->managed_system = managed_system;
    phyp_driver->uuid_table = uuid_table;
    if ((phyp_driver->caps = phypCapsInit()) == NULL) {
        virReportOOMError();
        goto failure;
    }

    conn->privateData = phyp_driver;
    conn->networkPrivateData = connection_data;
    if (phypUUIDTable_Init(conn) == -1)
        goto failure;

    if ((phyp_driver->vios_id = phypGetVIOSPartitionID(conn)) == -1)
        goto failure;

    return VIR_DRV_OPEN_SUCCESS;

  failure:
    if (phyp_driver != NULL) {
        virCapabilitiesFree(phyp_driver->caps);
        VIR_FREE(phyp_driver->managed_system);
        VIR_FREE(phyp_driver);
    }

    phypUUIDTable_Free(uuid_table);

    if (session != NULL) {
        libssh2_session_disconnect(session, "Disconnecting...");
        libssh2_session_free(session);
    }

    VIR_FREE(connection_data);
    VIR_FREE(string);

    return VIR_DRV_OPEN_ERROR;
}

static int
phypClose(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;

    libssh2_session_disconnect(session, "Disconnecting...");
    libssh2_session_free(session);

    virCapabilitiesFree(phyp_driver->caps);
    phypUUIDTable_Free(phyp_driver->uuid_table);
    VIR_FREE(phyp_driver->managed_system);
    VIR_FREE(phyp_driver);
    VIR_FREE(connection_data);
    return 0;
}


static int
phypIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Phyp uses an SSH tunnel, so is always encrypted */
    return 1;
}


static int
phypIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Phyp uses an SSH tunnel, so is always secure */
    return 1;
}


LIBSSH2_SESSION *
openSSHSession(virConnectPtr conn, virConnectAuthPtr auth,
               int *internal_socket)
{
    LIBSSH2_SESSION *session;
    const char *hostname = conn->uri->server;
    const char *username = conn->uri->user;
    const char *password = NULL;
    int sock;
    int rc;
    struct addrinfo *ai = NULL, *cur;
    struct addrinfo hints;
    int ret;
    char *pubkey = NULL;
    char *pvtkey = NULL;
    char *userhome = virGetUserDirectory(geteuid());
    struct stat pvt_stat, pub_stat;

    if (userhome == NULL)
        goto err;

    if (virAsprintf(&pubkey, "%s/.ssh/id_rsa.pub", userhome) < 0) {
        virReportOOMError();
        goto err;
    }

    if (virAsprintf(&pvtkey, "%s/.ssh/id_rsa", userhome) < 0) {
        virReportOOMError();
        goto err;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    ret = getaddrinfo(hostname, "22", &hints, &ai);
    if (ret != 0) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   _("Error while getting %s address info"), hostname);
        goto err;
    }

    cur = ai;
    while (cur != NULL) {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock >= 0) {
            if (connect(sock, cur->ai_addr, cur->ai_addrlen) == 0) {
                goto connected;
            }
            close(sock);
        }
        cur = cur->ai_next;
    }

    PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
               _("Failed to connect to %s"), hostname);
    freeaddrinfo(ai);
    goto err;

  connected:

    (*internal_socket) = sock;

    /* Create a session instance */
    session = libssh2_session_init();
    if (!session)
        goto err;

    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(session, 0);

    while ((rc = libssh2_session_startup(session, sock)) ==
           LIBSSH2_ERROR_EAGAIN) ;
    if (rc) {
        PHYP_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Failure establishing SSH session."));
        goto disconnect;
    }

    /* Trying authentication by pubkey */
    if (stat(pvtkey, &pvt_stat) || stat(pubkey, &pub_stat)) {
        rc = LIBSSH2_ERROR_SOCKET_NONE;
        goto keyboard_interactive;
    }

    while ((rc =
            libssh2_userauth_publickey_fromfile(session, username,
                                                pubkey,
                                                pvtkey,
                                                NULL)) ==
           LIBSSH2_ERROR_EAGAIN) ;

  keyboard_interactive:
    if (rc == LIBSSH2_ERROR_SOCKET_NONE
        || rc == LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
        || rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
        int i;
        int hasPassphrase = 0;

        virConnectCredential creds[] = {
            {VIR_CRED_PASSPHRASE, "password", "Password", NULL, NULL, 0},
        };

        if (!auth || !auth->cb) {
            PHYP_ERROR(conn, VIR_ERR_AUTH_FAILED,
                       "%s", _("No authentication callback provided."));
            goto disconnect;
        }

        for (i = 0; i < auth->ncredtype; i++) {
            if (auth->credtype[i] == VIR_CRED_PASSPHRASE)
                hasPassphrase = 1;
        }

        if (!hasPassphrase) {
            PHYP_ERROR(conn, VIR_ERR_AUTH_FAILED,
                       "%s", _("Required credentials are not supported."));
            goto disconnect;
        }

        int res =
            (auth->cb) (creds, ARRAY_CARDINALITY(creds), auth->cbdata);

        if (res < 0) {
            PHYP_ERROR(conn, VIR_ERR_AUTH_FAILED,
                       "%s", _("Unable to fetch credentials."));
            goto disconnect;
        }

        if (creds[0].result) {
            password = creds[0].result;
        } else {
            PHYP_ERROR(conn, VIR_ERR_AUTH_FAILED,
                       "%s", _("Unable to get password certificates"));
            goto disconnect;
        }

        while ((rc =
                libssh2_userauth_password(session, username,
                                          password)) ==
               LIBSSH2_ERROR_EAGAIN) ;

        if (rc) {
            PHYP_ERROR(conn, VIR_ERR_AUTH_FAILED,
                       "%s", _("Authentication failed"));
            goto disconnect;
        } else
            goto exit;

    } else if (rc == LIBSSH2_ERROR_NONE) {
        goto exit;

    } else if (rc == LIBSSH2_ERROR_ALLOC || rc == LIBSSH2_ERROR_SOCKET_SEND
               || rc == LIBSSH2_ERROR_SOCKET_TIMEOUT) {
        goto err;
    }

  disconnect:
    libssh2_session_disconnect(session, "Disconnecting...");
    libssh2_session_free(session);
  err:
    VIR_FREE(userhome);
    VIR_FREE(pubkey);
    VIR_FREE(pvtkey);
    VIR_FREE(password);
    return NULL;

  exit:
    VIR_FREE(userhome);
    VIR_FREE(pubkey);
    VIR_FREE(pvtkey);
    VIR_FREE(password);
    return session;
}

/* this functions is the layer that manipulates the ssh channel itself
 * and executes the commands on the remote machine */
static char *
phypExec(LIBSSH2_SESSION * session, char *cmd, int *exit_status,
         virConnectPtr conn)
{
    LIBSSH2_CHANNEL *channel;
    ConnectionData *connection_data = conn->networkPrivateData;
    virBuffer tex_ret = VIR_BUFFER_INITIALIZER;
    char buffer[0x4000] = { 0 };
    int exitcode;
    int bytecount = 0;
    int sock = connection_data->sock;
    int rc = 0;

    /* Exec non-blocking on the remove host */
    while ((channel = libssh2_channel_open_session(session)) == NULL &&
           libssh2_session_last_error(session, NULL, NULL, 0) ==
           LIBSSH2_ERROR_EAGAIN) {
        waitsocket(sock, session);
    }

    if (channel == NULL) {
        goto err;
    }

    while ((rc = libssh2_channel_exec(channel, cmd)) ==
           LIBSSH2_ERROR_EAGAIN) {
        waitsocket(sock, session);
    }

    if (rc != 0) {
        goto err;
    }

    for (;;) {
        /* loop until we block */
        do {
            rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
            if (rc > 0) {
                bytecount += rc;
                virBufferVSprintf(&tex_ret, "%s", buffer);
            }
        }
        while (rc > 0);

        /* this is due to blocking that would occur otherwise so we loop on
         * this condition */
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock, session);
        } else {
            break;
        }
    }

    exitcode = 127;

    while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN) {
        waitsocket(sock, session);
    }

    if (rc == 0) {
        exitcode = libssh2_channel_get_exit_status(channel);
    }

    (*exit_status) = exitcode;
    libssh2_channel_free(channel);
    channel = NULL;
    goto exit;

  err:
    (*exit_status) = SSH_CMD_ERR;
    virBufferFreeAndReset(&tex_ret);
    return NULL;

  exit:
    if (virBufferError(&tex_ret)) {
        virBufferFreeAndReset(&tex_ret);
        virReportOOMError();
        return NULL;
    }
    return virBufferContentAndReset(&tex_ret);
}

/* return the lpar_id given a name and a managed system name */
static int
phypGetLparID(LIBSSH2_SESSION * session, const char *managed_system,
              const char *name, virConnectPtr conn)
{
    int exit_status = 0;
    int lpar_id = 0;
    char *char_ptr;
    char *cmd = NULL;
    char *ret = NULL;

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s --filter lpar_names=%s -F lpar_id",
                    managed_system, name) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &lpar_id) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return lpar_id;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

/* return the lpar name given a lpar_id and a managed system name */
static char *
phypGetLparNAME(LIBSSH2_SESSION * session, const char *managed_system,
                unsigned int lpar_id, virConnectPtr conn)
{
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s --filter lpar_ids=%d -F name",
                    managed_system, lpar_id) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    char *char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    VIR_FREE(cmd);
    return ret;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return NULL;
}


/* Search into the uuid_table for a lpar_uuid given a lpar_id
 * and a managed system name
 *
 * return:  0 - record found
 *         -1 - not found
 * */
int
phypGetLparUUID(unsigned char *uuid, int lpar_id, virConnectPtr conn)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;
    lparPtr *lpars = uuid_table->lpars;
    unsigned int i = 0;

    for (i = 0; i < uuid_table->nlpars; i++) {
        if (lpars[i]->id == lpar_id) {
            memmove(uuid, lpars[i]->uuid, VIR_UUID_BUFLEN);
            return 0;
        }
    }

    return -1;
}

/*
 * type:
 * 0 - maxmem
 * 1 - memory
 * */
unsigned long
phypGetLparMem(virConnectPtr conn, const char *managed_system, int lpar_id,
               int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int memory = 0;
    int exit_status = 0;

    if (type != 1 && type != 0)
        goto err;

    if (type) {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r mem --level lpar -F curr_mem "
                        "--filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError();
            goto err;
        }
    } else {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r mem --level lpar -F "
                        "curr_max_mem --filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError();
            goto err;
        }
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (virStrToLong_i(ret, &char_ptr, 10, &memory) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return memory;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

}

unsigned long
phypGetLparCPU(virConnectPtr conn, const char *managed_system, int lpar_id)
{
    return phypGetLparCPUGeneric(conn, managed_system, lpar_id, 0);
}

static int
phypGetLparCPUMAX(virDomainPtr dom)
{
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    char *managed_system = phyp_driver->managed_system;

    return phypGetLparCPUGeneric(dom->conn, managed_system, dom->id, 1);
}

unsigned long
phypGetLparCPUGeneric(virConnectPtr conn, const char *managed_system,
                      int lpar_id, int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int exit_status = 0;
    int vcpus = 0;

    if (type) {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r proc --level lpar -F "
                        "curr_max_procs --filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError();
            goto err;
        }
    } else {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r proc --level lpar -F "
                        "curr_procs --filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError();
            goto err;
        }
    }
    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (virStrToLong_i(ret, &char_ptr, 10, &vcpus) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return (unsigned long) vcpus;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;
}

int
phypGetRemoteSlot(virConnectPtr conn, const char *managed_system,
                  const char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int remote_slot = 0;
    int exit_status = 0;

    if (virAsprintf(&cmd,
                    "lshwres -m %s -r virtualio --rsubtype scsi -F "
                    "remote_slot_num --filter lpar_names=%s",
                    managed_system, lpar_name) < 0) {
        virReportOOMError();
        goto err;
    }
    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (virStrToLong_i(ret, &char_ptr, 10, &remote_slot) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return remote_slot;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

char *
phypGetBackingDevice(virConnectPtr conn, const char *managed_system,
                     char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    int remote_slot = 0;
    int exit_status = 0;
    char *char_ptr;
    char *backing_device = NULL;

    if ((remote_slot =
         phypGetRemoteSlot(conn, managed_system, lpar_name)) == -1)
        goto err;

    if (virAsprintf(&cmd,
                    "lshwres -m %s -r virtualio --rsubtype scsi -F "
                    "backing_devices --filter slots=%d",
                    managed_system, remote_slot) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    /* here is a little trick to deal returns of this kind:
     *
     * 0x8100000000000000//lv01
     *
     * the information we really need is only lv01, so we
     * need to skip a lot of things on the string.
     * */
    char_ptr = strchr(ret, '/');

    if (char_ptr) {
        char_ptr++;
        if (char_ptr[0] == '/')
            char_ptr++;
        else
            goto err;

        backing_device = strdup(char_ptr);

        if (backing_device == NULL) {
            virReportOOMError();
            goto err;
        }
    } else {
        backing_device = ret;
        ret = NULL;
    }

    char_ptr = strchr(backing_device, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return backing_device;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return NULL;

}

int
phypGetLparState(virConnectPtr conn, unsigned int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *managed_system = phyp_driver->managed_system;
    int state = VIR_DOMAIN_NOSTATE;

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s -F state --filter lpar_ids=%d",
                    managed_system, lpar_id) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto cleanup;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (STREQ(ret, "Running"))
        state = VIR_DOMAIN_RUNNING;
    else if (STREQ(ret, "Not Activated"))
        state = VIR_DOMAIN_SHUTOFF;
    else if (STREQ(ret, "Shutting Down"))
        state = VIR_DOMAIN_SHUTDOWN;

  cleanup:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return state;
}

int
phypGetVIOSPartitionID(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    int id = -1;
    char *char_ptr;
    char *managed_system = phyp_driver->managed_system;

    if (virAsprintf(&cmd,
                    "lssyscfg -m %s -r lpar -F lpar_id,lpar_env|grep "
                    "vioserver|sed -s 's/,.*$//g'", managed_system) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &id) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return id;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

int
phypDiskType(virConnectPtr conn, char *backing_device)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    char *char_ptr;
    char *managed_system = phyp_driver->managed_system;
    int vios_id = phyp_driver->vios_id;
    int disk_type = -1;

    if (virAsprintf(&cmd,
                    "viosvrcmd -m %s -p %d -c \"lssp -field name type "
                    "-fmt , -all|grep %s|sed -e 's/^.*,//g'\"",
                    managed_system, vios_id, backing_device) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto cleanup;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (STREQ(ret, "LVPOOL"))
        disk_type = VIR_DOMAIN_DISK_TYPE_BLOCK;
    else if (STREQ(ret, "FBPOOL"))
        disk_type = VIR_DOMAIN_DISK_TYPE_FILE;

  cleanup:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return disk_type;
}

/* This is a generic function that won't be used directly by
 * libvirt api. The function returns the number of domains
 * in different states: Running, Not Activated and all:
 *
 * type: 0 - Running
 *       1 - Not Activated
 *       * - All
 * */
static int
phypNumDomainsGeneric(virConnectPtr conn, unsigned int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int exit_status = 0;
    int ndom = 0;
    char *char_ptr;
    char *cmd = NULL;
    char *ret = NULL;
    char *managed_system = phyp_driver->managed_system;
    const char *state;

    if (type == 0)
        state = "|grep Running";
    else if (type == 1)
        state = "|grep \"Not Activated\"";
    else
        state = " ";

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s -F lpar_id,state %s |grep -c "
                    "^[0-9]*", managed_system, state) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &ndom) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return ndom;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypNumDefinedDomains(virConnectPtr conn)
{
    return phypNumDomainsGeneric(conn, 1);
}

static int
phypNumDomains(virConnectPtr conn)
{
    return phypNumDomainsGeneric(conn, 0);
}

/* This is a generic function that won't be used directly by
 * libvirt api. The function returns the ids of domains
 * in different states: Running, and all:
 *
 * type: 0 - Running
 *       1 - all
 * */
static int
phypListDomainsGeneric(virConnectPtr conn, int *ids, int nids,
                       unsigned int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    int got = 0;
    char *char_ptr;
    unsigned int i = 0, j = 0;
    char id_c[10];
    char *cmd = NULL;
    char *ret = NULL;
    const char *state;

    if (type == 0)
        state = "|grep Running";
    else
        state = " ";

    memset(id_c, 0, 10);

    if (virAsprintf
        (&cmd,
         "lssyscfg -r lpar -m %s -F lpar_id,state %s | sed -e 's/,.*$//g'",
         managed_system, state) < 0) {
        virReportOOMError();
        goto err;
    }
    ret = phypExec(session, cmd, &exit_status, conn);

    /* I need to parse the textual return in order to get the ret */
    if (exit_status < 0 || ret == NULL)
        goto err;
    else {
        while (got < nids) {
            if (ret[i] == '\0')
                break;
            else if (ret[i] == '\n') {
                if (virStrToLong_i(id_c, &char_ptr, 10, &ids[got]) == -1) {
                    VIR_ERROR("Cannot parse number from '%s'", id_c);
                    goto err;
                }
                memset(id_c, 0, 10);
                j = 0;
                got++;
            } else {
                id_c[j] = ret[i];
                j++;
            }
            i++;
        }
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypListDomains(virConnectPtr conn, int *ids, int nids)
{
    return phypListDomainsGeneric(conn, ids, nids, 0);
}

static int
phypListDefinedDomains(virConnectPtr conn, char **const names, int nnames)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    int got = 0;
    int i;
    char *cmd = NULL;
    char *ret = NULL;
    char *domains = NULL;
    char *char_ptr2 = NULL;

    if (virAsprintf
        (&cmd,
         "lssyscfg -r lpar -m %s -F name,state | grep \"Not Activated\" | "
         "sed -e 's/,.*$//g'", managed_system) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    /* I need to parse the textual return in order to get the domains */
    if (exit_status < 0 || ret == NULL)
        goto err;
    else {
        domains = ret;

        while (got < nnames) {
            char_ptr2 = strchr(domains, '\n');

            if (char_ptr2) {
                *char_ptr2 = '\0';
                if ((names[got++] = strdup(domains)) == NULL) {
                    virReportOOMError();
                    goto err;
                }
                char_ptr2++;
                domains = char_ptr2;
            } else
                break;
        }
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;

  err:
    for (i = 0; i < got; i++)
        VIR_FREE(names[i]);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static virDomainPtr
phypDomainLookupByName(virConnectPtr conn, const char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainPtr dom = NULL;
    int lpar_id = 0;
    char *managed_system = phyp_driver->managed_system;
    unsigned char lpar_uuid[VIR_UUID_BUFLEN];

    lpar_id = phypGetLparID(session, managed_system, lpar_name, conn);
    if (lpar_id == -1)
        return NULL;

    if (phypGetLparUUID(lpar_uuid, lpar_id, conn) == -1)
        return NULL;

    dom = virGetDomain(conn, lpar_name, lpar_uuid);

    if (dom)
        dom->id = lpar_id;

    return dom;
}

static virDomainPtr
phypDomainLookupByID(virConnectPtr conn, int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainPtr dom = NULL;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    unsigned char lpar_uuid[VIR_UUID_BUFLEN];

    char *lpar_name = phypGetLparNAME(session, managed_system, lpar_id,
                                      conn);

    if (phypGetLparUUID(lpar_uuid, lpar_id, conn) == -1)
        goto err;

    if (exit_status < 0)
        goto err;

    dom = virGetDomain(conn, lpar_name, lpar_uuid);

    if (dom)
        dom->id = lpar_id;

    VIR_FREE(lpar_name);
    return dom;

  err:
    VIR_FREE(lpar_name);
    return NULL;
}

static char *
phypDomainDumpXML(virDomainPtr dom, int flags)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainDef def;
    char *managed_system = phyp_driver->managed_system;

    memset(&def, 0, sizeof(virDomainDef));

    def.virtType = VIR_DOMAIN_VIRT_PHYP;
    def.id = dom->id;

    char *lpar_name = phypGetLparNAME(session, managed_system, def.id,
                                      dom->conn);

    if (lpar_name == NULL) {
        VIR_ERROR("%s", "Unable to determine domain's name.");
        goto err;
    }

    if (phypGetLparUUID(def.uuid, dom->id, dom->conn) == -1) {
        VIR_ERROR("%s", "Unable to generate random uuid.");
        goto err;
    }

    if ((def.maxmem =
         phypGetLparMem(dom->conn, managed_system, dom->id, 0)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's max memory.");
        goto err;
    }

    if ((def.memory =
         phypGetLparMem(dom->conn, managed_system, dom->id, 1)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's memory.");
        goto err;
    }

    if ((def.vcpus =
         phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's CPU.");
        goto err;
    }

    return virDomainDefFormat(&def, flags);

  err:
    return NULL;
}

static int
phypDomainResume(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;

    if (virAsprintf
        (&cmd,
         "chsysstate -m %s -r lpar -o on --id %d -f %s",
         managed_system, dom->id, dom->name) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypDomainShutdown(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;

    if (virAsprintf
        (&cmd,
         "chsysstate -m %s -r lpar -o shutdown --id %d",
         managed_system, dom->id) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;
}

static int
phypDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    char *managed_system = phyp_driver->managed_system;

    info->state = phypGetLparState(dom->conn, dom->id);

    if ((info->maxMem =
         phypGetLparMem(dom->conn, managed_system, dom->id, 0)) == 0)
        VIR_WARN("%s", "Unable to determine domain's max memory.");

    if ((info->memory =
         phypGetLparMem(dom->conn, managed_system, dom->id, 1)) == 0)
        VIR_WARN("%s", "Unable to determine domain's memory.");

    if ((info->nrVirtCpu =
         phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0)
        VIR_WARN("%s", "Unable to determine domain's CPU.");

    return 0;
}

static int
phypDomainDestroy(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;

    if (virAsprintf
        (&cmd,
         "rmsyscfg -m %s -r lpar --id %d", managed_system, dom->id) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0)
        goto err;

    if (phypUUIDTable_RemLpar(dom->conn, dom->id) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;

}

static virDomainPtr
phypDomainCreateAndStart(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags ATTRIBUTE_UNUSED)
{

    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainDefPtr def = NULL;
    virDomainPtr dom = NULL;
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;
    lparPtr *lpars = uuid_table->lpars;
    unsigned int i = 0;
    char *managed_system = phyp_driver->managed_system;

    if (!(def = virDomainDefParseString(phyp_driver->caps, xml,
                                        VIR_DOMAIN_XML_SECURE)))
        goto err;

    /* checking if this name already exists on this system */
    if (phypGetLparID(session, managed_system, def->name, conn) == -1) {
        VIR_WARN("%s", "LPAR name already exists.");
        goto err;
    }

    /* checking if ID or UUID already exists on this system */
    for (i = 0; i < uuid_table->nlpars; i++) {
        if (lpars[i]->id == def->id || lpars[i]->uuid == def->uuid) {
            VIR_WARN("%s", "LPAR ID or UUID already exists.");
            goto err;
        }
    }

    if ((dom = virGetDomain(conn, def->name, def->uuid)) == NULL)
        goto err;

    if (phypBuildLpar(conn, def) == -1)
        goto err;

    if (phypDomainResume(dom) == -1)
        goto err;

    return dom;

  err:
    virDomainDefFree(def);
    if (dom)
        virUnrefDomain(dom);
    return NULL;
}

static char *
phypConnectGetCapabilities(virConnectPtr conn)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    char *xml;

    if ((xml = virCapabilitiesFormatXML(phyp_driver->caps)) == NULL)
        virReportOOMError();

    return xml;
}

virCapsPtr
phypCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine, 0, 0)) == NULL)
        goto no_memory;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN0
            ("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    /* XXX shouldn't 'borrow' KVM's prefix */
    virCapabilitiesSetMacPrefix(caps, (unsigned char[]) {
                                0x52, 0x54, 0x00});

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "linux",
                                         utsname.machine,
                                         sizeof(int) == 4 ? 32 : 8,
                                         NULL, NULL, 0, NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "phyp", NULL, NULL, 0, NULL) == NULL)
        goto no_memory;

    return caps;

  no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

static int
phypDomainSetCPU(virDomainPtr dom, unsigned int nvcpus)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    char operation;
    unsigned long ncpus = 0;
    unsigned int amount = 0;

    if ((ncpus = phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0)
        goto err;

    if (nvcpus > phypGetLparCPUMAX(dom)) {
        VIR_ERROR("%s",
                  "You are trying to set a number of CPUs bigger than "
                  "the max possible..");
        goto err;
    }

    if (ncpus > nvcpus) {
        operation = 'r';
        amount = nvcpus - ncpus;
    } else if (ncpus < nvcpus) {
        operation = 'a';
        amount = nvcpus - ncpus;
    } else
        goto exit;

    if (virAsprintf
        (&cmd,
         "chhwres -r proc -m %s --id %d -o %c --procunits %d 2>&1 |sed"
         "-e 's/^.*\\([0-9]\\+.[0-9]\\+\\).*$/\\1/g'",
         managed_system, dom->id, operation, amount) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0) {
        VIR_ERROR("%s",
                  "Possibly you don't have IBM Tools installed in your LPAR."
                  "Contact your support to enable this feature.");
        goto err;
    }

  exit:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

}

virDriver phypDriver = {
    VIR_DRV_PHYP,
    "PHYP",
    phypOpen,                   /* open */
    phypClose,                  /* close */
    NULL,                       /* supports_feature */
    NULL,                       /* type */
    NULL,                       /* version */
    NULL,                       /* libvirtVersion (impl. in libvirt.c) */
    NULL,                       /* getHostname */
    NULL,                       /* getMaxVcpus */
    NULL,                       /* nodeGetInfo */
    phypConnectGetCapabilities, /* getCapabilities */
    phypListDomains,            /* listDomains */
    phypNumDomains,             /* numOfDomains */
    phypDomainCreateAndStart,   /* domainCreateXML */
    phypDomainLookupByID,       /* domainLookupByID */
    NULL,                       /* domainLookupByUUID */
    phypDomainLookupByName,     /* domainLookupByName */
    NULL,                       /* domainSuspend */
    phypDomainResume,           /* domainResume */
    phypDomainShutdown,         /* domainShutdown */
    NULL,                       /* domainReboot */
    phypDomainDestroy,          /* domainDestroy */
    NULL,                       /* domainGetOSType */
    NULL,                       /* domainGetMaxMemory */
    NULL,                       /* domainSetMaxMemory */
    NULL,                       /* domainSetMemory */
    phypDomainGetInfo,          /* domainGetInfo */
    NULL,                       /* domainSave */
    NULL,                       /* domainRestore */
    NULL,                       /* domainCoreDump */
    phypDomainSetCPU,           /* domainSetVcpus */
    NULL,                       /* domainPinVcpu */
    NULL,                       /* domainGetVcpus */
    phypGetLparCPUMAX,          /* domainGetMaxVcpus */
    NULL,                       /* domainGetSecurityLabel */
    NULL,                       /* nodeGetSecurityModel */
    phypDomainDumpXML,          /* domainDumpXML */
    NULL,                       /* domainXMLFromNative */
    NULL,                       /* domainXMLToNative */
    phypListDefinedDomains,     /* listDefinedDomains */
    phypNumDefinedDomains,      /* numOfDefinedDomains */
    NULL,                       /* domainCreate */
    NULL,                       /* domainDefineXML */
    NULL,                       /* domainUndefine */
    NULL,                       /* domainAttachDevice */
    NULL,                       /* domainAttachDeviceFlags */
    NULL,                       /* domainDetachDevice */
    NULL,                       /* domainDetachDeviceFlags */
    NULL,                       /* domainGetAutostart */
    NULL,                       /* domainSetAutostart */
    NULL,                       /* domainGetSchedulerType */
    NULL,                       /* domainGetSchedulerParameters */
    NULL,                       /* domainSetSchedulerParameters */
    NULL,                       /* domainMigratePrepare */
    NULL,                       /* domainMigratePerform */
    NULL,                       /* domainMigrateFinish */
    NULL,                       /* domainBlockStats */
    NULL,                       /* domainInterfaceStats */
    NULL,                       /* domainMemoryStats */
    NULL,                       /* domainBlockPeek */
    NULL,                       /* domainMemoryPeek */
    NULL,                       /* nodeGetCellsFreeMemory */
    NULL,                       /* getFreeMemory */
    NULL,                       /* domainEventRegister */
    NULL,                       /* domainEventDeregister */
    NULL,                       /* domainMigratePrepare2 */
    NULL,                       /* domainMigrateFinish2 */
    NULL,                       /* nodeDeviceDettach */
    NULL,                       /* nodeDeviceReAttach */
    NULL,                       /* nodeDeviceReset */
    NULL,                       /* domainMigratePrepareTunnel */
    phypIsEncrypted,
    phypIsSecure,
    NULL,                       /* domainIsActive */
    NULL,                       /* domainIsPersistent */
    NULL,                       /* cpuCompare */
    NULL,                       /* cpuBaseline */
    NULL, /* domainGetJobInfo */
    NULL, /* domainAbortJob */
};

int
phypBuildLpar(virConnectPtr conn, virDomainDefPtr def)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;

    if (virAsprintf
        (&cmd,
         "mksyscfg -m %s -r lpar -p %s -i min_mem=%d,desired_mem=%d,"
         "max_mem=%d,desired_procs=%d,virtual_scsi_adapters=%s",
         managed_system, def->name, (int) def->memory,
         (int) def->memory, (int) def->maxmem, (int) def->vcpus,
         def->disks[0]->src) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0) {
        VIR_ERROR("%s\"%s\"", "Unable to create LPAR. Reason: ", ret);
        goto err;
    }

    if (phypUUIDTable_AddLpar(conn, def->uuid, def->id) == -1) {
        VIR_ERROR("%s", "Unable to add LPAR to the table");
        goto err;
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

int
phypUUIDTable_RemLpar(virConnectPtr conn, int id)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;
    unsigned int i = 0;

    for (i = 0; i <= uuid_table->nlpars; i++) {
        if (uuid_table->lpars[i]->id == id) {
            uuid_table->lpars[i]->id = -1;
            memset(uuid_table->lpars[i]->uuid, 0, VIR_UUID_BUFLEN);
        }
    }

    if (phypUUIDTable_WriteFile(conn) == -1)
        goto err;

    if (phypUUIDTable_Push(conn) == -1)
        goto err;

    return 0;

  err:
    return -1;
}

int
phypUUIDTable_AddLpar(virConnectPtr conn, unsigned char *uuid, int id)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;

    uuid_table->nlpars++;
    unsigned int i = uuid_table->nlpars;
    i--;

    if (VIR_REALLOC_N(uuid_table->lpars, uuid_table->nlpars) < 0) {
        virReportOOMError();
        goto err;
    }

    if (VIR_ALLOC(uuid_table->lpars[i]) < 0) {
        virReportOOMError();
        goto err;
    }

    uuid_table->lpars[i]->id = id;
    memmove(uuid_table->lpars[i]->uuid, uuid, VIR_UUID_BUFLEN);

    if (phypUUIDTable_WriteFile(conn) == -1)
        goto err;

    if (phypUUIDTable_Push(conn) == -1)
        goto err;

    return 0;

  err:
    return -1;
}

int
phypUUIDTable_ReadFile(virConnectPtr conn)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;
    unsigned int i = 0;
    int fd = -1;
    char local_file[] = "./uuid_table";
    int rc = 0;
    int id;

    if ((fd = open(local_file, O_RDONLY)) == -1) {
        VIR_WARN("%s", "Unable to write information to local file.");
        goto err;
    }

    /* Creating a new data base and writing to local file */
    if (VIR_ALLOC_N(uuid_table->lpars, uuid_table->nlpars) >= 0) {
        for (i = 0; i < uuid_table->nlpars; i++) {

            rc = read(fd, &id, sizeof(int));
            if (rc == sizeof(int)) {
                if (VIR_ALLOC(uuid_table->lpars[i]) < 0) {
                    virReportOOMError();
                    goto err;
                }
                uuid_table->lpars[i]->id = id;
            } else {
                VIR_WARN("%s",
                         "Unable to read from information to local file.");
                goto err;
            }

            rc = read(fd, uuid_table->lpars[i]->uuid, VIR_UUID_BUFLEN);
            if (rc != VIR_UUID_BUFLEN) {
                VIR_WARN("%s",
                         "Unable to read information to local file.");
                goto err;
            }
        }
    } else
        virReportOOMError();

    close(fd);
    return 0;

  err:
    close(fd);
    return -1;
}

int
phypUUIDTable_WriteFile(virConnectPtr conn)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    uuid_tablePtr uuid_table = phyp_driver->uuid_table;
    unsigned int i = 0;
    int fd = -1;
    char local_file[] = "./uuid_table";

    if ((fd = creat(local_file, 0755)) == -1)
        goto err;

    for (i = 0; i < uuid_table->nlpars; i++) {
        if (safewrite(fd, &uuid_table->lpars[i]->id,
                      sizeof(uuid_table->lpars[i]->id)) !=
            sizeof(uuid_table->lpars[i]->id)) {
            VIR_ERROR("%s", "Unable to write information to local file.");
            goto err;
        }

        if (safewrite(fd, uuid_table->lpars[i]->uuid, VIR_UUID_BUFLEN) !=
            VIR_UUID_BUFLEN) {
            VIR_ERROR("%s", "Unable to write information to local file.");
            goto err;
        }
    }

    close(fd);
    return 0;

  err:
    close(fd);
    return -1;
}

int
phypUUIDTable_Init(virConnectPtr conn)
{
    uuid_tablePtr uuid_table;
    phyp_driverPtr phyp_driver;
    int nids = 0;
    int *ids = NULL;
    unsigned int i = 0;

    if ((nids = phypNumDomainsGeneric(conn, 2)) < 0)
        goto err;

    /* exit early if there are no domains */
    if (nids == 0)
        return 0;

    if (VIR_ALLOC_N(ids, nids) < 0) {
        virReportOOMError();
        goto err;
    }

    if ((nids = phypListDomainsGeneric(conn, ids, nids, 1)) < 0)
        goto err;

    /* exit early if there are no domains */
    /* FIXME: phypNumDomainsGeneric() returned > 0 but phypListDomainsGeneric()
     *        returned 0. indicates this an error condition?
     *        an even stricter check would be to treat
     *
     *          phypNumDomainsGeneric() != phypListDomainsGeneric()
     *
     *        as an error */
    if (nids == 0) {
        VIR_FREE(ids);
        return 0;
    }

    phyp_driver = conn->privateData;
    uuid_table = phyp_driver->uuid_table;
    uuid_table->nlpars = nids;

    /* try to get the table from server */
    if (phypUUIDTable_Pull(conn) == -1) {
        /* file not found in the server, creating a new one */
        if (VIR_ALLOC_N(uuid_table->lpars, uuid_table->nlpars) >= 0) {
            for (i = 0; i < uuid_table->nlpars; i++) {
                if (VIR_ALLOC(uuid_table->lpars[i]) < 0) {
                    virReportOOMError();
                    goto err;
                }
                uuid_table->lpars[i]->id = ids[i];

                if (virUUIDGenerate(uuid_table->lpars[i]->uuid) < 0)
                    VIR_WARN("%s %d", "Unable to generate UUID for domain",
                             ids[i]);
            }
        } else {
            virReportOOMError();
            goto err;
        }

        if (phypUUIDTable_WriteFile(conn) == -1)
            goto err;

        if (phypUUIDTable_Push(conn) == -1)
            goto err;
    } else {
        if (phypUUIDTable_ReadFile(conn) == -1)
            goto err;
        goto exit;
    }

  exit:
    VIR_FREE(ids);
    return 0;

  err:
    VIR_FREE(ids);
    return -1;
}

void
phypUUIDTable_Free(uuid_tablePtr uuid_table)
{
    int i;

    if (uuid_table == NULL)
        return;

    for (i = 0; i < uuid_table->nlpars; i++)
        VIR_FREE(uuid_table->lpars[i]);

    VIR_FREE(uuid_table->lpars);
    VIR_FREE(uuid_table);
}

int
phypUUIDTable_Push(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    LIBSSH2_CHANNEL *channel = NULL;
    struct stat local_fileinfo;
    char buffer[1024];
    int rc = 0;
    FILE *fd;
    size_t nread, sent;
    char *ptr;
    char remote_file[] = "/home/hscroot/libvirt_uuid_table";
    char local_file[] = "./uuid_table";

    if (stat(local_file, &local_fileinfo) == -1) {
        VIR_WARN0("Unable to stat local file.");
        goto err;
    }

    if (!(fd = fopen(local_file, "rb"))) {
        VIR_WARN0("Unable to open local file.");
        goto err;
    }

    do {
        channel =
            libssh2_scp_send(session, remote_file,
                             0x1FF & local_fileinfo.st_mode,
                             (unsigned long) local_fileinfo.st_size);

        if ((!channel) && (libssh2_session_last_errno(session) !=
                           LIBSSH2_ERROR_EAGAIN))
            goto err;
    } while (!channel);

    do {
        nread = fread(buffer, 1, sizeof(buffer), fd);
        if (nread <= 0) {
            if (feof(fd)) {
                /* end of file */
                break;
            } else {
                VIR_ERROR("Failed to read from '%s'", local_file);
                goto err;
            }
        }
        ptr = buffer;
        sent = 0;

        do {
            /* write the same data over and over, until error or completion */
            rc = libssh2_channel_write(channel, ptr, nread);
            if (LIBSSH2_ERROR_EAGAIN == rc) {   /* must loop around */
                continue;
            } else if (rc > 0) {
                /* rc indicates how many bytes were written this time */
                sent += rc;
            }
            ptr += sent;
            nread -= sent;
        } while (rc > 0 && sent < nread);
    } while (1);

    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_wait_closed(channel);
        libssh2_channel_free(channel);
        channel = NULL;
    }
    return 0;

  err:
    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_wait_closed(channel);
        libssh2_channel_free(channel);
        channel = NULL;
    }
    return -1;
}

int
phypUUIDTable_Pull(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    LIBSSH2_CHANNEL *channel = NULL;
    struct stat fileinfo;
    char buffer[1024];
    int rc = 0;
    int fd;
    int got = 0;
    int amount = 0;
    int total = 0;
    int sock = 0;
    char remote_file[] = "/home/hscroot/libvirt_uuid_table";
    char local_file[] = "./uuid_table";

    /* Trying to stat the remote file. */
    do {
        channel = libssh2_scp_recv(session, remote_file, &fileinfo);

        if (!channel) {
            if (libssh2_session_last_errno(session) !=
                LIBSSH2_ERROR_EAGAIN) {
                goto err;;
            } else {
                waitsocket(sock, session);
            }
        }
    } while (!channel);

    /* Creating a new data base based on remote file */
    if ((fd = creat(local_file, 0755)) == -1)
        goto err;

    /* Request a file via SCP */
    while (got < fileinfo.st_size) {
        do {
            amount = sizeof(buffer);

            if ((fileinfo.st_size - got) < amount) {
                amount = fileinfo.st_size - got;
            }

            rc = libssh2_channel_read(channel, buffer, amount);
            if (rc > 0) {
                if (safewrite(fd, buffer, rc) != rc)
                    VIR_WARN("%s",
                             "Unable to write information to local file.");

                got += rc;
                total += rc;
            }
        } while (rc > 0);

        if ((rc == LIBSSH2_ERROR_EAGAIN)
            && (got < fileinfo.st_size)) {
            /* this is due to blocking that would occur otherwise
             * so we loop on this condition */

            waitsocket(sock, session);  /* now we wait */
            continue;
        }
        break;
    }
    close(fd);
    goto exit;

  exit:
    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_wait_closed(channel);
        libssh2_channel_free(channel);
        channel = NULL;
    }
    return 0;

  err:
    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_wait_closed(channel);
        libssh2_channel_free(channel);
        channel = NULL;
    }
    return -1;
}

int
escape_specialcharacters(char *src, char *dst, size_t dstlen)
{
    size_t len = strlen(src);
    char temp_buffer[len];
    unsigned int i = 0, j = 0;
    if (len == 0)
        return -1;

    for (i = 0; i < len; i++) {
        switch (src[i]) {
            case '&':
            case ';':
            case '`':
            case '@':
            case '"':
            case '|':
            case '*':
            case '?':
            case '~':
            case '<':
            case '>':
            case '^':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '$':
            case '%':
            case '#':
            case '\\':
            case '\n':
            case '\r':
            case '\t':
                continue;
            default:
                temp_buffer[j] = src[i];
                j++;
        }
    }
    temp_buffer[j] = '\0';

    if (virStrcpy(dst, temp_buffer, dstlen) == NULL)
        return -1;

    return 0;
}

int
waitsocket(int socket_fd, LIBSSH2_SESSION * session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);

    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

int
phypRegister(void)
{
    virRegisterDriver(&phypDriver);
    return 0;
}
