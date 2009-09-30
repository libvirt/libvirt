
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

#include "phyp_driver.h"

#define VIR_FROM_THIS VIR_FROM_PHYP

#define PHYP_CMD_DEBUG VIR_DEBUG("COMMAND:%s\n",cmd);

static int escape_specialcharacters(char *src, char *dst, size_t dstlen);

/*
 * URI: phyp://user@[hmc|ivm]/managed_system
 * */

static virDrvOpenStatus
phypOpen(virConnectPtr conn,
         virConnectAuthPtr auth, int flags ATTRIBUTE_UNUSED)
{
    LIBSSH2_SESSION *session = NULL;
    ConnectionData *connection_data = NULL;
    char *string;
    size_t len = 0;
    uuid_dbPtr uuid_db = NULL;
    int internal_socket;

    if (!conn || !conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->scheme == NULL || STRNEQ(conn->uri->scheme, "phyp"))
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->server == NULL) {
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                      _("Missing server name in phyp:// URI"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (conn->uri->path == NULL) {
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                      _("Missing path name in phyp:// URI"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (VIR_ALLOC(uuid_db) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    if (VIR_ALLOC(connection_data) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    len = strlen(conn->uri->path) + 1;

    if (VIR_ALLOC_N(string, len) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    if (escape_specialcharacters(conn->uri->path, string, len) == -1) {
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                      _("Error parsing 'path'. Invalid characters."));
        goto failure;
    }

    if ((session = openSSHSession(conn, auth, &internal_socket)) == NULL) {
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                      _("Error while opening SSH session."));
        goto failure;
    }
    //conn->uri->path = string;
    connection_data->session = session;
    connection_data->auth = auth;

    uuid_db->nlpars = 0;
    uuid_db->lpars = NULL;

    conn->privateData = uuid_db;
    conn->networkPrivateData = connection_data;
    init_uuid_db(conn);

    return VIR_DRV_OPEN_SUCCESS;

  failure:
    VIR_FREE(uuid_db);
    VIR_FREE(connection_data);
    VIR_FREE(string);

    return VIR_DRV_OPEN_ERROR;
}

static int
phypClose(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;

    libssh2_session_disconnect(session, "Disconnecting...");
    libssh2_session_free(session);

    VIR_FREE(connection_data);
    return 0;
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

    memset (&hints, '\0', sizeof (hints));
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    ret = getaddrinfo (hostname, "22", &hints, &ai);
    if (ret != 0) {
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                      _("Error while getting %s address info"),
                      hostname);
        goto err;
    }

    cur = ai;
    while (cur != NULL) {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock >= 0) {
            if (connect (sock, cur->ai_addr, cur->ai_addrlen) == 0) {
                goto connected;
            }
            close (sock);
        }
        cur = cur->ai_next;
    }

    virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                  VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                  _("Failed to connect to %s"), hostname);
    freeaddrinfo (ai);
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
        virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                      VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                      _("Failure establishing SSH session."));
        goto err;
    }

    /* Trying authentication by pubkey */
    while ((rc =
            libssh2_userauth_publickey_fromfile(session, username,
                                                "/home/user/"
                                                ".ssh/id_rsa.pub",
                                                "/home/user/"
                                                ".ssh/id_rsa",
                                                password)) ==
           LIBSSH2_ERROR_EAGAIN) ;
    if (rc) {
        int i;
        int hasPassphrase = 0;

        virConnectCredential creds[] = {
            {VIR_CRED_PASSPHRASE, "password", "Password", NULL, NULL, 0},
        };

        if (!auth || !auth->cb) {
            virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                          VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                          _("No authentication callback provided."));
            goto err;
        }

        for (i = 0; i < auth->ncredtype; i++) {
            if (auth->credtype[i] == VIR_CRED_PASSPHRASE)
                hasPassphrase = 1;
        }

        if (!hasPassphrase) {
            virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                          VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                          _("Required credentials are not supported."));
            goto err;
        }

        int res =
            (auth->cb) (creds, ARRAY_CARDINALITY(creds), auth->cbdata);

        if (res < 0) {
            virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                          VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                          _("Unable to fetch credentials."));
            goto err;
        }

        if (creds[0].result) {
            password = creds[0].result;
        } else {
            virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                          VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                          _("Unable to get password certificates"));
            libssh2_session_disconnect(session, "Disconnecting...");
            libssh2_session_free(session);
            goto err;
        }

        while ((rc =
                libssh2_userauth_password(session, username,
                                          password)) ==
               LIBSSH2_ERROR_EAGAIN) ;

        if (rc) {
            virRaiseError(conn, NULL, NULL, 0, VIR_FROM_PHYP,
                          VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0, "%s",
                          _("Authentication failed"));
            libssh2_session_disconnect(session, "Disconnecting");
            libssh2_session_free(session);
            goto err;
        } else
            goto exit;
    }
  err:
    return NULL;

  exit:
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
    char *cleanup_buf = virBufferContentAndReset(&tex_ret);

    VIR_FREE(cleanup_buf);
    return NULL;

  exit:
    if (virBufferError(&tex_ret)) {
        virReportOOMError(conn);
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
    char *cmd;

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s --filter lpar_names=%s -F lpar_id",
                    managed_system, name) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    const char *ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &lpar_id) == -1)
        goto err;

    VIR_FREE(cmd);
    return lpar_id;

  err:
    VIR_FREE(cmd);
    return -1;
}

/* return the lpar name given a lpar_id and a managed system name */
static char *
phypGetLparNAME(LIBSSH2_SESSION * session, const char *managed_system,
                unsigned int lpar_id, virConnectPtr conn)
{
    char *cmd;
    int exit_status = 0;

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s --filter lpar_ids=%d -F name",
                    managed_system, lpar_id) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char *char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (exit_status < 0 || ret == NULL)
        goto err;

    VIR_FREE(cmd);
    return ret;

  err:
    VIR_FREE(cmd);
    return NULL;
}


/* Search into the uuid_db for a lpar_uuid given a lpar_id
 * and a managed system name
 *
 * return:  0 - record found
 *         -1 - not found
 * */
int
phypGetLparUUID(unsigned char *uuid, int lpar_id, virConnectPtr conn)
{
    uuid_dbPtr uuid_db = conn->privateData;
    lparPtr *lpars = uuid_db->lpars;
    unsigned int i = 0;

    for (i = 0; i < uuid_db->nlpars; i++) {
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
    char *cmd;
    char *char_ptr;
    int memory = 0;
    int exit_status = 0;

    if (type != 1 && type != 0)
        goto err;

    if (type) {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r mem --level lpar -F curr_mem --filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError(conn);
            goto err;
        }
    } else {
        if (virAsprintf(&cmd,
                        "lshwres -m %s -r mem --level lpar -F curr_max_mem --filter lpar_ids=%d",
                        managed_system, lpar_id) < 0) {
            virReportOOMError(conn);
            goto err;
        }
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char *mem_char_ptr = strchr(ret, '\n');

    if (mem_char_ptr)
        *mem_char_ptr = '\0';

    if (exit_status < 0)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &memory) == -1)
        goto err;

    VIR_FREE(cmd);
    return memory;

  err:
    VIR_FREE(cmd);
    return 0;

}

unsigned long
phypGetLparCPU(virConnectPtr conn, const char *managed_system, int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd;
    int exit_status = 0;
    int vcpus = 0;

    if (virAsprintf(&cmd,
                    "lshwres -m %s -r proc --level lpar -F curr_procs --filter lpar_ids=%d",
                    managed_system, lpar_id) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;
    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char *char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (virStrToLong_i(ret, &char_ptr, 10, &vcpus) == -1)
        goto err;

    if (exit_status < 0)
        goto err;

    VIR_FREE(cmd);
    return (unsigned long) vcpus;

  err:
    VIR_FREE(cmd);
    return 0;
}

int
phypGetRemoteSlot(virConnectPtr conn, const char *managed_system,
                  const char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd;
    char *char_ptr;
    int remote_slot = 0;
    int exit_status = 0;

    if (virAsprintf(&cmd,
                    "lshwres -m %s -r virtualio --rsubtype scsi -F remote_slot_num --filter lpar_names=%s",
                    managed_system, lpar_name) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;
    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char *char_ptr2 = strchr(ret, '\n');

    if (char_ptr2)
        *char_ptr2 = '\0';

    if (exit_status < 0)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &remote_slot) == -1)
        goto err;

    VIR_FREE(cmd);
    return remote_slot;

  err:
    VIR_FREE(cmd);
    return 0;
}

char *
phypGetBackingDevice(virConnectPtr conn, const char *managed_system,
                     char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd;
    int remote_slot = 0;
    int exit_status = 0;

    if ((remote_slot =
         phypGetRemoteSlot(conn, managed_system, lpar_name)) == 0)
        goto err;

    if (virAsprintf(&cmd,
                    "lshwres -m %s -r virtualio --rsubtype scsi -F backing_devices --filter slots=%d",
                    managed_system, remote_slot) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    /* here is a little trick to deal returns of this kind:
     *
     * 0x8100000000000000//lv01
     *
     * the information we really need is only lv01, so we
     * need to skip a lot of things on the string.
     * */
    char *backing_device = strchr(ret, '/');

    if (backing_device) {
        backing_device++;
        if (backing_device[0] == '/')
            backing_device++;
        else
            goto err;
    } else {
        backing_device = ret;
    }

    char *char_ptr = strchr(backing_device, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (exit_status < 0 || backing_device == NULL)
        goto err;

    VIR_FREE(cmd);
    return backing_device;

  err:
    VIR_FREE(cmd);
    return NULL;

}

int
phypGetLparState(virConnectPtr conn, unsigned int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *managed_system = conn->uri->path;

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */

    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s -F state --filter lpar_ids=%d",
                    managed_system, lpar_id) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (exit_status < 0 || ret == NULL)
        goto err;

    VIR_FREE(cmd);
    if (STREQ(ret, "Running"))
        return VIR_DOMAIN_RUNNING;
    else if (STREQ(ret, "Not Activated"))
        return VIR_DOMAIN_SHUTOFF;
    else if (STREQ(ret, "Shutting Down"))
        return VIR_DOMAIN_SHUTDOWN;
    else
        goto err;

  err:
    VIR_FREE(cmd);
    return VIR_DOMAIN_NOSTATE;
}

int
phypDiskType(virConnectPtr conn, char *backing_device)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd;
    int exit_status = 0;

    if (virAsprintf(&cmd,
                    "ioscli lssp -field name type -fmt , -all|grep %s|sed -e 's/^.*,//g'",
                    backing_device) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (ret == NULL)
        goto err;

    char *char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (exit_status < 0 || ret == NULL)
        goto err;

    VIR_FREE(cmd);
    if (STREQ(ret, "LVPOOL"))
        return VIR_DOMAIN_DISK_TYPE_BLOCK;
    else if (STREQ(ret, "FBPOOL"))
        return VIR_DOMAIN_DISK_TYPE_FILE;
    else
        goto err;

  err:
    VIR_FREE(cmd);
    return -1;
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
    LIBSSH2_SESSION *session = connection_data->session;
    int exit_status = 0;
    int ndom = 0;
    char *char_ptr;
    char *cmd;
    char *managed_system = conn->uri->path;
    const char *state;

    if (type == 0)
        state = "|grep Running";
    else if (type == 1)
        state = "|grep \"Not Activated\"";
    else
        state = " ";

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */

    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (virAsprintf(&cmd,
                    "lssyscfg -r lpar -m %s -F lpar_id,state %s |grep -c ^[0-9]*",
                    managed_system, state) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &ndom) == -1)
        goto err;

    VIR_FREE(cmd);
    return ndom;

  err:
    VIR_FREE(cmd);
    return 0;
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
 *       * - all
 * */
static int
phypListDomainsGeneric(virConnectPtr conn, int *ids, int nids,
                       unsigned int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = conn->uri->path;
    int exit_status = 0;
    int got = 0;
    char *char_ptr;
    unsigned int i = 0, j = 0;
    char id_c[10];
    char *cmd;
    const char *state;

    if (type == 0)
        state = "|grep Running";
    else
        state = " ";

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    memset(id_c, 0, 10);

    if (virAsprintf
        (&cmd,
         "lssyscfg -r lpar -m %s -F lpar_id,state %s | sed -e 's/,.*$//g'",
         managed_system, state) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;
    char *ret = phypExec(session, cmd, &exit_status, conn);

    /* I need to parse the textual return in order to get the ret */
    if (exit_status < 0 || ret == NULL)
        goto err;
    else {
        while (got < nids) {
            if (ret[i] == '\n') {
                if (virStrToLong_i(id_c, &char_ptr, 10, &ids[got]) == -1)
                    return 0;
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
    return got;

  err:
    VIR_FREE(cmd);
    return 0;
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
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = conn->uri->path;
    int exit_status = 0;
    int got = 0;
    char *char_ptr = NULL;
    char *cmd;
    char *domains;

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (virAsprintf
        (&cmd,
         "lssyscfg -r lpar -m %s -F name,state | grep \"Not Activated\" | sed -e 's/,.*$//g'",
         managed_system) < 0) {
        virReportOOMError(conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, conn);

    if (VIR_ALLOC(domains) < 0)
        virReportOOMError(conn);

    domains = strdup(ret);
    if (!domains)
        goto err;

    char *char_ptr2 = NULL;
    /* I need to parse the textual return in order to get the domains */
    if (exit_status < 0 || domains == NULL)
        goto err;
    else {
        while (got < nnames) {
            char_ptr2 = strchr(domains, '\n');

            if (char_ptr2) {
                *char_ptr2 = '\0';
                if (!strdup(domains))
                    goto err;
                names[got] = strdup(domains);
                char_ptr2++;
                domains = char_ptr2;
                got++;
            }
        }
    }

    VIR_FREE(domains);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;

  err:
    VIR_FREE(domains);
    VIR_FREE(ret);
    return 0;
}

static virDomainPtr
phypDomainLookupByName(virConnectPtr conn, const char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainPtr dom = NULL;
    int lpar_id = 0;
    char *managed_system = conn->uri->path;
    unsigned char *lpar_uuid = NULL;

    if (VIR_ALLOC_N(lpar_uuid, VIR_UUID_BUFLEN) < 0)
        virReportOOMError(dom->conn);

    /* need to shift one byte in order to remove the first "/" of uri component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char *char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    lpar_id = phypGetLparID(session, managed_system, lpar_name, conn);
    if (lpar_id < 0)
        goto err;

    if (phypGetLparUUID(lpar_uuid, lpar_id, conn) == -1)
        goto err;

    dom = virGetDomain(conn, lpar_name, lpar_uuid);

    if (dom)
        dom->id = lpar_id;

    VIR_FREE(lpar_uuid);
    return dom;

  err:
    VIR_FREE(lpar_uuid);
    return NULL;
}

static virDomainPtr
phypDomainLookupByID(virConnectPtr conn, int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainPtr dom = NULL;
    char *managed_system = conn->uri->path;
    int exit_status = 0;
    unsigned char *lpar_uuid = NULL;

    if (VIR_ALLOC_N(lpar_uuid, VIR_UUID_BUFLEN) < 0)
        virReportOOMError(dom->conn);

    /* need to shift one byte in order to remove the first "/" of uri component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char *char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

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
    VIR_FREE(lpar_uuid);
    return dom;

  err:
    VIR_FREE(lpar_name);
    VIR_FREE(lpar_uuid);
    return NULL;
}

static char *
phypDomainDumpXML(virDomainPtr dom, int flags)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    char *managed_system = dom->conn->uri->path;
    unsigned char *lpar_uuid = NULL;

    if (VIR_ALLOC_N(lpar_uuid, VIR_UUID_BUFLEN) < 0)
        virReportOOMError(dom->conn);

    if (VIR_ALLOC(def) < 0)
        virReportOOMError(dom->conn);

    /* need to shift one byte in order to remove the first "/" of uri component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char *char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    def->virtType = VIR_DOMAIN_VIRT_PHYP;
    def->id = dom->id;

    char *lpar_name = phypGetLparNAME(session, managed_system, def->id,
                                      dom->conn);

    if (lpar_name == NULL) {
        VIR_ERROR("%s", "Unable to determine domain's name.");
        goto err;
    }

    if (phypGetLparUUID(lpar_uuid, dom->id, dom->conn) == -1) {
        VIR_ERROR("%s", "Unable to generate random uuid.");
        goto err;
    }

    if (!memcpy(def->uuid, lpar_uuid, VIR_UUID_BUFLEN)) {
        VIR_ERROR("%s", "Unable to generate random uuid.");
        goto err;
    }

    if ((def->maxmem =
         phypGetLparMem(dom->conn, managed_system, dom->id, 0)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's max memory.");
        goto err;
    }

    if ((def->memory =
         phypGetLparMem(dom->conn, managed_system, dom->id, 1)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's memory.");
        goto err;
    }

    if ((def->vcpus =
         phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0) {
        VIR_ERROR("%s", "Unable to determine domain's CPU.");
        goto err;
    }

    ret = virDomainDefFormat(dom->conn, def, flags);

  err:
    VIR_FREE(def);
    return ret;
}

static int
phypDomainResume(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = dom->conn->uri->path;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *cmd;

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (virAsprintf
        (&cmd,
         "chsysstate -m %s -r lpar -o on --id %d -f %s",
         managed_system, dom->id, dom->name) < 0) {
        virReportOOMError(dom->conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, dom->conn);

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

}

static int
phypDomainShutdown(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = dom->conn->uri->path;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *cmd;

    /* need to shift one byte in order to remove the first "/" of URI component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

    if (virAsprintf
        (&cmd,
         "chsysstate -m %s -r lpar -o shutdown --id %d",
         managed_system, dom->id) < 0) {
        virReportOOMError(dom->conn);
        goto err;
    }
    PHYP_CMD_DEBUG;

    char *ret = phypExec(session, cmd, &exit_status, dom->conn);

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

}

static int
phypDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    char *managed_system = dom->conn->uri->path;

    /* need to shift one byte in order to remove the first "/" of uri component */
    if (managed_system[0] == '/')
        managed_system++;

    /* here we are handling only the first component of the path,
     * so skipping the second:
     * */
    char *char_ptr = strchr(managed_system, '/');

    if (char_ptr)
        *char_ptr = '\0';

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

virDriver phypDriver = {
    VIR_DRV_PHYP,
    "PHYP",
    phypOpen,                   /* open */
    phypClose,                  /* close */
    NULL,                       /* supports_feature */
    NULL,                       /* type */
    NULL,                       /* version */
    NULL,                       /* getHostname */
    NULL,                       /* getMaxVcpus */
    NULL,                       /* nodeGetInfo */
    NULL,                       /* getCapabilities */
    phypListDomains,            /* listDomains */
    phypNumDomains,             /* numOfDomains */
    NULL,                       /* domainCreateXML */
    phypDomainLookupByID,       /* domainLookupByID */
    NULL,                       /* domainLookupByUUID */
    phypDomainLookupByName,     /* domainLookupByName */
    NULL,                       /* domainSuspend */
    phypDomainResume,           /* domainResume */
    phypDomainShutdown,         /* domainShutdown */
    NULL,                       /* domainReboot */
    NULL,                       /* domainDestroy */
    NULL,                       /* domainGetOSType */
    NULL,                       /* domainGetMaxMemory */
    NULL,                       /* domainSetMaxMemory */
    NULL,                       /* domainSetMemory */
    phypDomainGetInfo,          /* domainGetInfo */
    NULL,                       /* domainSave */
    NULL,                       /* domainRestore */
    NULL,                       /* domainCoreDump */
    NULL,                       /* domainSetVcpus */
    NULL,                       /* domainPinVcpu */
    NULL,                       /* domainGetVcpus */
    NULL,                       /* domainGetMaxVcpus */
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
    NULL,                       /* domainDetachDevice */
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
};

int
phypRegister(void)
{
    virRegisterDriver(&phypDriver);
    return 0;
}

void
init_uuid_db(virConnectPtr conn)
{
    uuid_dbPtr uuid_db;
    int nids = 0;
    int *ids = NULL;
    unsigned int i = 0;

    if ((nids = phypNumDomainsGeneric(conn, 2)) == 0)
        goto exit;

    if (VIR_ALLOC_N(ids, nids) < 0)
        virReportOOMError(conn);

    if (VIR_ALLOC(uuid_db) < 0)
        virReportOOMError(conn);

    if (phypListDomainsGeneric(conn, ids, nids, 1) == 0)
        goto exit;

    uuid_db = conn->privateData;
    uuid_db->nlpars = nids;

    if (VIR_ALLOC_N(uuid_db->lpars, uuid_db->nlpars) >= 0) {
        for (i = 0; i < uuid_db->nlpars; i++) {
            if (VIR_ALLOC(uuid_db->lpars[i]) < 0)
                virReportOOMError(conn);
            uuid_db->lpars[i]->id = ids[i];

            if (virUUIDGenerate(uuid_db->lpars[i]->uuid) < 0)
                VIR_WARN("%s %d", "Unable to generate UUID for domain",
                         ids[i]);
        }
    }
  exit:
    VIR_FREE(ids);
    return;
}

static int
escape_specialcharacters(char *src, char *dst, size_t dstlen)
{
    size_t len = strlen(src);
    char temp_buffer[len];
    unsigned int i = 0, j = 0;
    if (len == 0)
        return -1;

    for (i = 0; i < len; i++) {
        switch (src[i]) {
            case '&': case ';': case '`': case '@':
            case '"': case '|': case '*': case '?':
            case '~': case '<': case '>': case '^':
            case '(': case ')': case '[': case ']':
            case '{': case '}': case '$': case '%':
            case '#': case '\\': case '\n': case '\r':
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

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

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
