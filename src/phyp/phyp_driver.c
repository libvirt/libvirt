
/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
#include "authhelper.h"
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
#include "storage_conf.h"
#include "nodeinfo.h"
#include "files.h"

#include "phyp_driver.h"

#define VIR_FROM_THIS VIR_FROM_PHYP

#define PHYP_ERROR(code, ...)                                                 \
    virReportErrorHelper(NULL, VIR_FROM_PHYP, code, __FILE__, __FUNCTION__,   \
                         __LINE__, __VA_ARGS__)

/*
 * URI: phyp://user@[hmc|ivm]/managed_system
 * */

static unsigned const int HMC = 0;
static unsigned const int IVM = 127;

static int
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

/* this function is the layer that manipulates the ssh channel itself
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

static int
phypGetSystemType(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;

    if (virAsprintf(&cmd, "lshmc -V") < 0) {
        virReportOOMError();
        exit_status = -1;
    }
    ret = phypExec(session, cmd, &exit_status, conn);

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return exit_status;
}

static int
phypGetVIOSPartitionID(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    int id = -1;
    char *char_ptr;
    char *managed_system = phyp_driver->managed_system;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferAddLit(&buf, " -r lpar -F lpar_id,lpar_env"
                    "|sed -n '/vioserver/ {\n s/,.*$//\n p\n}'");
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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

static virCapsPtr
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
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    int ndom = 0;
    char *char_ptr;
    char *cmd = NULL;
    char *ret = NULL;
    char *managed_system = phyp_driver->managed_system;
    const char *state;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (type == 0)
        state = "|grep Running";
    else if (type == 1) {
        if (system_type == HMC) {
            state = "|grep \"Not Activated\"";
        } else {
            state = "|grep \"Open Firmware\"";
        }
    } else
        state = " ";

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -F lpar_id,state %s |grep -c '^[0-9]*'",
                      state);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    int got = -1;
    char *cmd = NULL;
    char *ret = NULL;
    char *line, *next_line;
    const char *state;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (type == 0)
        state = "|grep Running";
    else
        state = " ";

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -F lpar_id,state %s | sed -e 's/,.*$//'",
                      state);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    /* I need to parse the textual return in order to get the ids */
    line = ret;
    got = 0;
    while (*line && got < nids) {
        if (virStrToLong_i(line, &next_line, 10, &ids[got]) == -1) {
            VIR_ERROR(_("Cannot parse number from '%s'"), line);
            got = -1;
            goto err;
        }
        got++;
        line = next_line;
        while (*line == '\n')
            line++; /* skip \n */
    }

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;
}

static int
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
            VIR_ERROR0(_("Unable to write information to local file."));
            goto err;
        }

        if (safewrite(fd, uuid_table->lpars[i]->uuid, VIR_UUID_BUFLEN) !=
            VIR_UUID_BUFLEN) {
            VIR_ERROR0(_("Unable to write information to local file."));
            goto err;
        }
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Could not close %s"),
                             local_file);
        goto err;
    }
    return 0;

  err:
    VIR_FORCE_CLOSE(fd);
    return -1;
}

static int
phypUUIDTable_Push(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    LIBSSH2_CHANNEL *channel = NULL;
    virBuffer username = VIR_BUFFER_INITIALIZER;
    struct stat local_fileinfo;
    char buffer[1024];
    int rc = 0;
    FILE *fd;
    size_t nread, sent;
    char *ptr;
    char local_file[] = "./uuid_table";
    char *remote_file = NULL;

    if (conn->uri->user != NULL) {
        virBufferVSprintf(&username, "%s", conn->uri->user);

        if (virBufferError(&username)) {
            virBufferFreeAndReset(&username);
            virReportOOMError();
            goto err;
        }
    }

    if (virAsprintf
        (&remote_file, "/home/%s/libvirt_uuid_table",
         virBufferContentAndReset(&username))
        < 0) {
        virReportOOMError();
        goto err;
    }

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
                VIR_ERROR(_("Failed to read from %s"), local_file);
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
    virBufferFreeAndReset(&username);
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

static int
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

static int
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

static int
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
        VIR_WARN0("Unable to write information to local file.");
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
                VIR_WARN0
                    ("Unable to read from information to local file.");
                goto err;
            }

            rc = read(fd, uuid_table->lpars[i]->uuid, VIR_UUID_BUFLEN);
            if (rc != VIR_UUID_BUFLEN) {
                VIR_WARN0("Unable to read information to local file.");
                goto err;
            }
        }
    } else
        virReportOOMError();

    VIR_FORCE_CLOSE(fd);
    return 0;

  err:
    VIR_FORCE_CLOSE(fd);
    return -1;
}

static int
phypUUIDTable_Pull(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    LIBSSH2_CHANNEL *channel = NULL;
    virBuffer username = VIR_BUFFER_INITIALIZER;
    struct stat fileinfo;
    char buffer[1024];
    int rc = 0;
    int fd;
    int got = 0;
    int amount = 0;
    int total = 0;
    int sock = 0;
    char local_file[] = "./uuid_table";
    char *remote_file = NULL;

    if (conn->uri->user != NULL) {
        virBufferVSprintf(&username, "%s", conn->uri->user);

        if (virBufferError(&username)) {
            virBufferFreeAndReset(&username);
            virReportOOMError();
            goto err;
        }
    }

    if (virAsprintf
        (&remote_file, "/home/%s/libvirt_uuid_table",
         virBufferContentAndReset(&username))
        < 0) {
        virReportOOMError();
        goto err;
    }

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
                    VIR_WARN0
                        ("Unable to write information to local file.");

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
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Could not close %s"),
                             local_file);
        goto err;
    }
    goto exit;

  exit:
    if (channel) {
        libssh2_channel_send_eof(channel);
        libssh2_channel_wait_eof(channel);
        libssh2_channel_wait_closed(channel);
        libssh2_channel_free(channel);
        channel = NULL;
    }
    virBufferFreeAndReset(&username);
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

static int
phypUUIDTable_Init(virConnectPtr conn)
{
    uuid_tablePtr uuid_table;
    phyp_driverPtr phyp_driver;
    int nids_numdomains = 0;
    int nids_listdomains = 0;
    int *ids = NULL;
    unsigned int i = 0;

    if ((nids_numdomains = phypNumDomainsGeneric(conn, 2)) < 0)
        goto err;

    if (VIR_ALLOC_N(ids, nids_numdomains) < 0) {
        virReportOOMError();
        goto err;
    }

    if ((nids_listdomains =
         phypListDomainsGeneric(conn, ids, nids_numdomains, 1)) < 0)
        goto err;

    /* exit early if there are no domains */
    if (nids_numdomains == 0 && nids_listdomains == 0)
        goto exit;
    else if (nids_numdomains != nids_listdomains) {
        VIR_ERROR0(_("Unable to determine number of domains."));
        goto err;
    }

    phyp_driver = conn->privateData;
    uuid_table = phyp_driver->uuid_table;
    uuid_table->nlpars = nids_listdomains;

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
                    VIR_WARN("Unable to generate UUID for domain %d",
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

static void
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

static LIBSSH2_SESSION *
openSSHSession(virConnectPtr conn, virConnectAuthPtr auth,
               int *internal_socket)
{
    LIBSSH2_SESSION *session;
    const char *hostname = conn->uri->server;
    char *username = NULL;
    char *password = NULL;
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

    if (conn->uri->user != NULL) {
        username = strdup(conn->uri->user);

        if (username == NULL) {
            virReportOOMError();
            goto err;
        }
    } else {
        if (auth == NULL || auth->cb == NULL) {
            PHYP_ERROR(VIR_ERR_AUTH_FAILED,
                       "%s", _("No authentication callback provided."));
            goto err;
        }

        username = virRequestUsername(auth, NULL, conn->uri->server);

        if (username == NULL) {
            PHYP_ERROR(VIR_ERR_AUTH_FAILED, "%s",
                       _("Username request failed"));
            goto err;
        }
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    ret = getaddrinfo(hostname, "22", &hints, &ai);
    if (ret != 0) {
        PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
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
            VIR_FORCE_CLOSE(sock);
        }
        cur = cur->ai_next;
    }

    PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
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
        PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
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
        if (auth == NULL || auth->cb == NULL) {
            PHYP_ERROR(VIR_ERR_AUTH_FAILED,
                       "%s", _("No authentication callback provided."));
            goto disconnect;
        }

        password = virRequestPassword(auth, username, conn->uri->server);

        if (password == NULL) {
            PHYP_ERROR(VIR_ERR_AUTH_FAILED, "%s",
                       _("Password request failed"));
            goto disconnect;
        }

        while ((rc =
                libssh2_userauth_password(session, username,
                                          password)) ==
               LIBSSH2_ERROR_EAGAIN) ;

        if (rc) {
            PHYP_ERROR(VIR_ERR_AUTH_FAILED,
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
    VIR_FREE(username);
    VIR_FREE(password);
    return NULL;

  exit:
    VIR_FREE(userhome);
    VIR_FREE(pubkey);
    VIR_FREE(pvtkey);
    VIR_FREE(username);
    VIR_FREE(password);
    return session;
}

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
    char *managed_system = NULL;

    if (!conn || !conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->scheme == NULL || STRNEQ(conn->uri->scheme, "phyp"))
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->server == NULL) {
        PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing server name in phyp:// URI"));
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

    if (conn->uri->path) {
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
            PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Error parsing 'path'. Invalid characters."));
            goto failure;
        }
    }

    if ((session = openSSHSession(conn, auth, &internal_socket)) == NULL) {
        PHYP_ERROR(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Error while opening SSH session."));
        goto failure;
    }

    connection_data->session = session;

    uuid_table->nlpars = 0;
    uuid_table->lpars = NULL;

    if (conn->uri->path)
        phyp_driver->managed_system = managed_system;

    phyp_driver->uuid_table = uuid_table;
    if ((phyp_driver->caps = phypCapsInit()) == NULL) {
        virReportOOMError();
        goto failure;
    }

    conn->privateData = phyp_driver;
    conn->networkPrivateData = connection_data;

    if ((phyp_driver->system_type = phypGetSystemType(conn)) == -1)
        goto failure;

    if (phypUUIDTable_Init(conn) == -1)
        goto failure;

    if (phyp_driver->system_type == HMC) {
        if ((phyp_driver->vios_id = phypGetVIOSPartitionID(conn)) == -1)
            goto failure;
    }

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

static int
phypIsUpdated(virDomainPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

/* return the lpar_id given a name and a managed system name */
static int
phypGetLparID(LIBSSH2_SESSION * session, const char *managed_system,
              const char *name, virConnectPtr conn)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    int lpar_id = 0;
    char *char_ptr;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " --filter lpar_names=%s -F lpar_id", name);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " --filter lpar_ids=%d -F name", lpar_id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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
static int
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
static unsigned long
phypGetLparMem(virConnectPtr conn, const char *managed_system, int lpar_id,
               int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int memory = 0;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (type != 1 && type != 0)
        return 0;

    virBufferAddLit(&buf, "lshwres");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -r mem --level lpar -F %s --filter lpar_ids=%d",
                      type ? "curr_mem" : "curr_max_mem", lpar_id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return 0;
    }
    cmd = virBufferContentAndReset(&buf);

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

static unsigned long
phypGetLparCPUGeneric(virConnectPtr conn, const char *managed_system,
                      int lpar_id, int type)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int exit_status = 0;
    int vcpus = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lshwres");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -r proc --level lpar -F %s --filter lpar_ids=%d",
                      type ? "curr_max_procs" : "curr_procs", lpar_id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return 0;
    }
    cmd = virBufferContentAndReset(&buf);

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

static unsigned long
phypGetLparCPU(virConnectPtr conn, const char *managed_system, int lpar_id)
{
    return phypGetLparCPUGeneric(conn, managed_system, lpar_id, 0);
}

static int
phypDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    char *managed_system = phyp_driver->managed_system;

    if (flags != (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        PHYP_ERROR(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    return phypGetLparCPUGeneric(dom->conn, managed_system, dom->id, 1);
}

static int
phypGetLparCPUMAX(virDomainPtr dom)
{
    return phypDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE |
                                         VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
phypGetRemoteSlot(virConnectPtr conn, const char *managed_system,
                  const char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    char *char_ptr;
    int remote_slot = 0;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lshwres");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r virtualio --rsubtype scsi -F "
                      "remote_slot_num --filter lpar_names=%s", lpar_name);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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

/* XXX - is this needed? */
static char *phypGetBackingDevice(virConnectPtr, const char *, char *)
    ATTRIBUTE_UNUSED;
static char *
phypGetBackingDevice(virConnectPtr conn, const char *managed_system,
                     char *lpar_name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int remote_slot = 0;
    int exit_status = 0;
    char *char_ptr;
    char *backing_device = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if ((remote_slot =
         phypGetRemoteSlot(conn, managed_system, lpar_name)) == -1)
        return NULL;

    virBufferAddLit(&buf, "lshwres");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r virtualio --rsubtype scsi -F "
                      "backing_devices --filter slots=%d", remote_slot);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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

static char *
phypGetLparProfile(virConnectPtr conn, int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -r prof --filter lpar_ids=%d -F name|head -n 1",
                      lpar_id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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

static int
phypGetVIOSNextSlotNumber(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *char_ptr;
    char *cmd = NULL;
    char *ret = NULL;
    char *profile = NULL;
    int slot = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!(profile = phypGetLparProfile(conn, vios_id))) {
        VIR_ERROR0(_("Unable to get VIOS profile name."));
        goto err;
    }

    virBufferAddLit(&buf, "lssyscfg");

    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);

    virBufferVSprintf(&buf, " -r prof --filter "
                      "profile_names=%s -F virtual_eth_adapters,"
                      "virtual_opti_pool_id,virtual_scsi_adapters,"
                      "virtual_serial_adapters|sed -e 's/\"//g' -e "
                      "'s/,/\\n/g'|sed -e 's/\\(^[0-9][0-9]\\*\\).*$/\\1/'"
                      "|sort|tail -n 1", profile);

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }

    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &slot) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return slot + 1;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypCreateServerSCSIAdapter(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    char *profile = NULL;
    int slot = 0;
    char *vios_name = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!
        (vios_name =
         phypGetLparNAME(session, managed_system, vios_id, conn))) {
        VIR_ERROR0(_("Unable to get VIOS name"));
        goto err;
    }

    if (!(profile = phypGetLparProfile(conn, vios_id))) {
        VIR_ERROR0(_("Unable to get VIOS profile name."));
        goto err;
    }

    if ((slot = phypGetVIOSNextSlotNumber(conn)) == -1) {
        VIR_ERROR0(_("Unable to get free slot number"));
        goto err;
    }

    /* Listing all the virtual_scsi_adapter interfaces, the new adapter must
     * be appended to this list
     * */
    virBufferAddLit(&buf, "lssyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r prof --filter lpar_ids=%d,profile_names=%s"
                      " -F virtual_scsi_adapters|sed -e s/\\\"//g",
                      vios_id, profile);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    /* Here I change the VIOS configuration to append the new adapter
     * with the free slot I got with phypGetVIOSNextSlotNumber.
     * */
    virBufferAddLit(&buf, "chsyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r prof -i 'name=%s,lpar_id=%d,"
                      "\"virtual_scsi_adapters=%s,%d/server/any/any/1\"'",
                      vios_name, vios_id, ret, slot);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    /* Finally I add the new scsi adapter to VIOS using the same slot
     * I used in the VIOS configuration.
     * */
    virBufferAddLit(&buf, "chhwres -r virtualio --rsubtype scsi");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -p %s -o a -s %d -d 0 -a \"adapter_type=server\"",
                      vios_name, slot);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    VIR_FREE(profile);
    VIR_FREE(vios_name);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(profile);
    VIR_FREE(vios_name);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static char *
phypGetVIOSFreeSCSIAdapter(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lsmap -all -field svsa backing -fmt , ");

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed '/,[^.*]/d; s/,//g; q'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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


static int
phypAttachDevice(virDomainPtr domain, const char *xml)
{

    virConnectPtr conn = domain->conn;
    ConnectionData *connection_data = domain->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = domain->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *cmd = NULL;
    char *ret = NULL;
    char *scsi_adapter = NULL;
    int slot = 0;
    char *vios_name = NULL;
    char *profile = NULL;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *domain_name = NULL;

    if (VIR_ALLOC_N(domain_name, sizeof(domain->name)) < 0) {
        virReportOOMError();
        goto err;
    }

    if (escape_specialcharacters
        (domain->name, domain_name, strlen(domain->name)) == -1) {
        virReportOOMError();
        goto err;
    }

    def->os.type = strdup("aix");

    if (def->os.type == NULL) {
        virReportOOMError();
        goto err;
    }

    dev = virDomainDeviceDefParse(phyp_driver->caps, def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (!dev) {
        virReportOOMError();
        goto err;
    }

    if (!
        (vios_name =
         phypGetLparNAME(session, managed_system, vios_id, conn))) {
        VIR_ERROR0(_("Unable to get VIOS name"));
        goto err;
    }

    /* First, let's look for a free SCSI Adapter
     * */
    if (!(scsi_adapter = phypGetVIOSFreeSCSIAdapter(conn))) {
        /* If not found, let's create one.
         * */
        if (phypCreateServerSCSIAdapter(conn) == -1) {
            VIR_ERROR0(_("Unable to create new virtual adapter"));
            goto err;
        } else {
            if (!(scsi_adapter = phypGetVIOSFreeSCSIAdapter(conn))) {
                VIR_ERROR0(_("Unable to create new virtual adapter"));
                goto err;
            }
        }
    }

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "mkvdev -vdev %s -vadapter %s",
                      dev->data.disk->src, scsi_adapter);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (!(profile = phypGetLparProfile(conn, domain->id))) {
        VIR_ERROR0(_("Unable to get VIOS profile name."));
        goto err;
    }

    /* Let's get the slot number for the adapter we just created
     * */
    virBufferAddLit(&buf, "lshwres -r virtualio --rsubtype scsi");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " slot_num,backing_device|grep %s|cut -d, -f1",
                      dev->data.disk->src);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &slot) == -1)
        goto err;

    /* Listing all the virtual_scsi_adapter interfaces, the new adapter must
     * be appended to this list
     * */
    virBufferAddLit(&buf, "lssyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -r prof --filter lpar_ids=%d,profile_names=%s"
                      " -F virtual_scsi_adapters|sed -e 's/\"//g'",
                      vios_id, profile);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    /* Here I change the LPAR configuration to append the new adapter
     * with the new slot we just created
     * */
    virBufferAddLit(&buf, "chsyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -r prof -i 'name=%s,lpar_id=%d,"
                      "\"virtual_scsi_adapters=%s,%d/client/%d/%s/0\"'",
                      domain_name, domain->id, ret, slot,
                      vios_id, vios_name);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (virStrToLong_i(ret, &char_ptr, 10, &slot) == -1)
        goto err;

    /* Finally I add the new scsi adapter to VIOS using the same slot
     * I used in the VIOS configuration.
     * */
    virBufferAddLit(&buf, "chhwres -r virtualio --rsubtype scsi");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf,
                      " -p %s -o a -s %d -d 0 -a \"adapter_type=server\"",
                      domain_name, slot);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL) {
        VIR_ERROR0(_
                   ("Possibly you don't have IBM Tools installed in your LPAR."
                    "Contact your support to enable this feature."));
        goto err;
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    VIR_FREE(def);
    VIR_FREE(dev);
    VIR_FREE(vios_name);
    VIR_FREE(scsi_adapter);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    VIR_FREE(def);
    VIR_FREE(dev);
    VIR_FREE(vios_name);
    VIR_FREE(scsi_adapter);
    return -1;
}

static int
phypVolumeGetKey(virConnectPtr conn, char *key, const char *name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lslv %s -field lvid", name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed -e 's/^LV IDENTIFIER://' -e 's/ //g'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    char *char_ptr = strchr(ret, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (memcpy(key, ret, MAX_KEY_SIZE) == NULL)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static char *
phypGetStoragePoolDevice(virConnectPtr conn, char *name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lssp -detail -sp %s -field name", name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed '1d; s/ //g'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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

static unsigned long int
phypGetStoragePoolSize(virConnectPtr conn, char *name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    int vios_id = phyp_driver->vios_id;
    char *cmd = NULL;
    char *ret = NULL;
    int sp_size = 0;
    char *char_ptr;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lssp -detail -sp %s -field size", name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed '1d; s/ //g'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &sp_size) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return sp_size;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypBuildVolume(virConnectPtr conn, const char *lvname, const char *spname,
                unsigned int capacity, char *key)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int vios_id = phyp_driver->vios_id;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "mklv -lv %s %s %d", lvname, spname, capacity);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0) {
        VIR_ERROR(_("Unable to create Volume: %s"), ret);
        goto err;
    }

    if (phypVolumeGetKey(conn, key, lvname) == -1)
        goto err;;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static virStorageVolPtr
phypVolumeLookupByName(virStoragePoolPtr pool, const char *volname)
{

    char key[MAX_KEY_SIZE];

    if (phypVolumeGetKey(pool->conn, key, volname) == -1)
        return NULL;

    return virGetStorageVol(pool->conn, pool->name, volname, key);
}

static virStorageVolPtr
phypStorageVolCreateXML(virStoragePoolPtr pool,
                        const char *xml, unsigned int flags)
{
    virCheckFlags(0, NULL);

    virStorageVolDefPtr voldef = NULL;
    virStoragePoolDefPtr spdef = NULL;
    virStorageVolPtr vol = NULL;
    char *key = NULL;

    if (VIR_ALLOC(spdef) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (VIR_ALLOC_N(key, MAX_KEY_SIZE) < 0) {
        virReportOOMError();
        return NULL;
    }

    /* Filling spdef manually
     * */
    if (pool->name != NULL) {
        spdef->name = pool->name;
    } else {
        VIR_ERROR0(_("Unable to determine storage pool's name."));
        goto err;
    }

    if (memcpy(spdef->uuid, pool->uuid, VIR_UUID_BUFLEN) == NULL) {
        VIR_ERROR0(_("Unable to determine storage pool's uuid."));
        goto err;
    }

    if ((spdef->capacity =
         phypGetStoragePoolSize(pool->conn, pool->name)) == -1) {
        VIR_ERROR0(_("Unable to determine storage pools's size."));
        goto err;
    }

    /* Information not avaliable */
    spdef->allocation = 0;
    spdef->available = 0;

    spdef->source.ndevice = 1;

    /*XXX source adapter not working properly, should show hdiskX */
    if ((spdef->source.adapter =
         phypGetStoragePoolDevice(pool->conn, pool->name)) == NULL) {
        VIR_ERROR0(_("Unable to determine storage pools's source adapter."));
        goto err;
    }

    if ((voldef = virStorageVolDefParseString(spdef, xml)) == NULL) {
        VIR_ERROR0(_("Error parsing volume XML."));
        goto err;
    }

    /* checking if this name already exists on this system */
    if (phypVolumeLookupByName(pool, voldef->name) != NULL) {
        VIR_ERROR0(_("StoragePool name already exists."));
        goto err;
    }

    /* The key must be NULL, the Power Hypervisor creates a key
     * in the moment you create the volume.
     * */
    if (voldef->key) {
        VIR_ERROR0(_("Key must be empty, Power Hypervisor will create one for you."));
        goto err;
    }

    if (voldef->capacity) {
        VIR_ERROR0(_("Capacity cannot be empty."));
        goto err;
    }

    if (phypBuildVolume
        (pool->conn, voldef->name, spdef->name, voldef->capacity,
         key) == -1)
        goto err;

    if ((vol =
         virGetStorageVol(pool->conn, pool->name, voldef->name,
                          key)) == NULL)
        goto err;

    return vol;

  err:
    virStorageVolDefFree(voldef);
    virStoragePoolDefFree(spdef);
    if (vol)
        virUnrefStorageVol(vol);
    return NULL;
}

static char *
phypVolumeGetPhysicalVolumeByStoragePool(virStorageVolPtr vol, char *sp)
{
    virConnectPtr conn = vol->conn;
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lssp -detail -sp %s -field pvname", sp);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed 1d");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

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

static virStorageVolPtr
phypVolumeLookupByPath(virConnectPtr conn, const char *volname)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *spname = NULL;
    char *key = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lslv %s -field vgname", volname);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed -e 's/^VOLUME GROUP://g' -e 's/ //g'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

    spname = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || spname == NULL)
        return NULL;

    char *char_ptr = strchr(spname, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    if (VIR_ALLOC_N(key, MAX_KEY_SIZE) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (phypVolumeGetKey(conn, key, volname) == -1)
        return NULL;

    return virGetStorageVol(conn, spname, volname, key);
}

static int
phypGetStoragePoolUUID(virConnectPtr conn, unsigned char *uuid,
                       const char *name)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lsdev -dev %s -attr vgserial_id", name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed '1,2d'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (memmove(uuid, ret, VIR_UUID_BUFLEN) == NULL)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static virStoragePoolPtr
phypStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (phypGetStoragePoolUUID(conn, uuid, name) == -1)
        return NULL;

    return virGetStoragePool(conn, name, uuid);
}

static char *
phypVolumeGetXMLDesc(virStorageVolPtr vol, unsigned int flags)
{
    virCheckFlags(0, NULL);

    virStorageVolDef voldef;
    memset(&voldef, 0, sizeof(virStorageVolDef));

    virStoragePoolPtr sp =
        phypStoragePoolLookupByName(vol->conn, vol->pool);

    if (!sp)
        goto err;

    virStoragePoolDef pool;
    memset(&pool, 0, sizeof(virStoragePoolDef));

    if (VIR_ALLOC_N(voldef.key, MAX_KEY_SIZE) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (sp->name != NULL) {
        pool.name = sp->name;
    } else {
        VIR_ERROR0(_("Unable to determine storage sp's name."));
        goto err;
    }

    if (memmove(pool.uuid, sp->uuid, VIR_UUID_BUFLEN) == NULL) {
        VIR_ERROR0(_("Unable to determine storage sp's uuid."));
        goto err;
    }

    if ((pool.capacity = phypGetStoragePoolSize(sp->conn, sp->name)) == -1) {
        VIR_ERROR0(_("Unable to determine storage sps's size."));
        goto err;
    }

    /* Information not avaliable */
    pool.allocation = 0;
    pool.available = 0;

    pool.source.ndevice = 1;

    if ((pool.source.adapter =
         phypGetStoragePoolDevice(sp->conn, sp->name)) == NULL) {
        VIR_ERROR0(_("Unable to determine storage sps's source adapter."));
        goto err;
    }

    if (vol->name != NULL)
        voldef.name = vol->name;
    else {
        VIR_ERROR0(_("Unable to determine storage pool's name."));
        goto err;
    }

    if (memmove(voldef.key, vol->key, PATH_MAX) == NULL) {
        VIR_ERROR0(_("Unable to determine volume's key."));
        goto err;
    }

    voldef.type = VIR_STORAGE_POOL_LOGICAL;

    return virStorageVolDefFormat(&pool, &voldef);

  err:
    return NULL;
}

/* The Volume Group path here will be treated as suggested in the
 * email on the libvirt mailling list. As soon as I can't get the
 * path for every volume, the path will be a representation in
 * the form:
 *
 * /physical_volume/storage_pool/logical_volume
 *
 * */
static char *
phypVolumeGetPath(virStorageVolPtr vol)
{
    virConnectPtr conn = vol->conn;
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    char *cmd = NULL;
    char *sp = NULL;
    char *path = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lslv %s -field vgname", vol->name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf,
                      "|sed -e 's/^VOLUME GROUP://g' -e 's/ //g'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    cmd = virBufferContentAndReset(&buf);

    sp = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || sp == NULL)
        goto err;

    char *char_ptr = strchr(sp, '\n');

    if (char_ptr)
        *char_ptr = '\0';

    char *pv = phypVolumeGetPhysicalVolumeByStoragePool(vol, sp);

    if (pv) {
        if (virAsprintf(&path, "/%s/%s/%s", pv, sp, vol->name) < 0) {
            virReportOOMError();
            goto err;
        }
    } else {
        goto err;
    }

    VIR_FREE(cmd);
    return path;

  err:
    VIR_FREE(cmd);
    VIR_FREE(sp);
    VIR_FREE(path);
    return NULL;

}

static int
phypStoragePoolListVolumes(virStoragePoolPtr pool, char **const volumes,
                           int nvolumes)
{
    virConnectPtr conn = pool->conn;
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    int got = 0;
    int i;
    char *cmd = NULL;
    char *ret = NULL;
    char *volumes_list = NULL;
    char *char_ptr2 = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lsvg -lv %s -field lvname", pool->name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|sed '1,2d'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    /* I need to parse the textual return in order to get the volumes */
    if (exit_status < 0 || ret == NULL)
        goto err;
    else {
        volumes_list = ret;

        while (got < nvolumes) {
            char_ptr2 = strchr(volumes_list, '\n');

            if (char_ptr2) {
                *char_ptr2 = '\0';
                if ((volumes[got++] = strdup(volumes_list)) == NULL) {
                    virReportOOMError();
                    goto err;
                }
                char_ptr2++;
                volumes_list = char_ptr2;
            } else
                break;
        }
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;

  err:
    for (i = 0; i < got; i++)
        VIR_FREE(volumes[i]);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    virConnectPtr conn = pool->conn;
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    int nvolumes = 0;
    char *cmd = NULL;
    char *ret = NULL;
    char *managed_system = phyp_driver->managed_system;
    int vios_id = phyp_driver->vios_id;
    char *char_ptr;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);
    virBufferVSprintf(&buf, "lsvg -lv %s -field lvname", pool->name);
    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');
    virBufferVSprintf(&buf, "|grep -c '^.*$'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &nvolumes) == -1)
        goto err;

    /* We need to remove 2 line from the header text output */
    nvolumes -= 2;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return nvolumes;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypDestroyStoragePool(virStoragePoolPtr pool)
{
    virConnectPtr conn = pool->conn;
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int vios_id = phyp_driver->vios_id;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "rmsp %s", pool->name);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    if (virAsprintf(&cmd,
                    "viosvrcmd -m %s --id %d -c "
                    "'rmsp %s'", managed_system, vios_id,
                    pool->name) < 0) {
        virReportOOMError();
        goto err;
    }

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0) {
        VIR_ERROR(_("Unable to create Storage Pool: %s"), ret);
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

static int
phypBuildStoragePool(virConnectPtr conn, virStoragePoolDefPtr def)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    virStoragePoolSource source = def->source;
    int vios_id = phyp_driver->vios_id;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "mksp -f %schild %s", def->name,
                      source.adapter);

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0) {
        VIR_ERROR(_("Unable to create Storage Pool: %s"), ret);
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

static int
phypNumOfStoragePools(virConnectPtr conn)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    int exit_status = 0;
    int nsp = 0;
    char *cmd = NULL;
    char *ret = NULL;
    char *managed_system = phyp_driver->managed_system;
    int vios_id = phyp_driver->vios_id;
    char *char_ptr;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lsvg");

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    virBufferVSprintf(&buf, "|grep -c '^.*$'");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0 || ret == NULL)
        goto err;

    if (virStrToLong_i(ret, &char_ptr, 10, &nsp) == -1)
        goto err;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return nsp;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static int
phypListStoragePools(virConnectPtr conn, char **const pools, int npools)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    char *managed_system = phyp_driver->managed_system;
    int system_type = phyp_driver->system_type;
    int vios_id = phyp_driver->vios_id;
    int exit_status = 0;
    int got = 0;
    int i;
    char *cmd = NULL;
    char *ret = NULL;
    char *storage_pools = NULL;
    char *char_ptr2 = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (system_type == HMC)
        virBufferVSprintf(&buf, "viosvrcmd -m %s --id %d -c '",
                          managed_system, vios_id);

    virBufferVSprintf(&buf, "lsvg");

    if (system_type == HMC)
        virBufferAddChar(&buf, '\'');

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    /* I need to parse the textual return in order to get the storage pools */
    if (exit_status < 0 || ret == NULL)
        goto err;
    else {
        storage_pools = ret;

        while (got < npools) {
            char_ptr2 = strchr(storage_pools, '\n');

            if (char_ptr2) {
                *char_ptr2 = '\0';
                if ((pools[got++] = strdup(storage_pools)) == NULL) {
                    virReportOOMError();
                    goto err;
                }
                char_ptr2++;
                storage_pools = char_ptr2;
            } else
                break;
        }
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return got;

  err:
    for (i = 0; i < got; i++)
        VIR_FREE(pools[i]);
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;
}

static virStoragePoolPtr
phypGetStoragePoolLookUpByUUID(virConnectPtr conn,
                               const unsigned char *uuid)
{
    virStoragePoolPtr sp = NULL;
    int npools = 0;
    int gotpools = 0;
    char **pools = NULL;
    unsigned int i = 0;
    unsigned char *local_uuid = NULL;

    if (VIR_ALLOC_N(local_uuid, VIR_UUID_BUFLEN) < 0) {
        virReportOOMError();
        goto err;
    }

    if ((npools = phypNumOfStoragePools(conn)) == -1) {
        virReportOOMError();
        goto err;
    }

    if (VIR_ALLOC_N(pools, npools) < 0) {
        virReportOOMError();
        goto err;
    }

    if ((gotpools = phypListStoragePools(conn, pools, npools)) == -1) {
        virReportOOMError();
        goto err;
    }

    if (gotpools != npools) {
        virReportOOMError();
        goto err;
    }

    for (i = 0; i < gotpools; i++) {
        if (phypGetStoragePoolUUID(conn, local_uuid, pools[i]) == -1)
            continue;

        if (!memcmp(local_uuid, uuid, VIR_UUID_BUFLEN)) {
            sp = virGetStoragePool(conn, pools[i], uuid);
            VIR_FREE(local_uuid);
            VIR_FREE(pools);

            if (sp)
                return sp;
            else
                goto err;
        }
    }

  err:
    VIR_FREE(local_uuid);
    VIR_FREE(pools);
    return NULL;
}

static virStoragePoolPtr
phypStoragePoolCreateXML(virConnectPtr conn,
                         const char *xml, unsigned int flags)
{
    virCheckFlags(0, NULL);

    virStoragePoolDefPtr def = NULL;
    virStoragePoolPtr sp = NULL;

    if (!(def = virStoragePoolDefParseString(xml)))
        goto err;

    /* checking if this name already exists on this system */
    if (phypStoragePoolLookupByName(conn, def->name) != NULL) {
        VIR_WARN0("StoragePool name already exists.");
        goto err;
    }

    /* checking if ID or UUID already exists on this system */
    if (phypGetStoragePoolLookUpByUUID(conn, def->uuid) != NULL) {
        VIR_WARN0("StoragePool uuid already exists.");
        goto err;
    }

    if ((sp = virGetStoragePool(conn, def->name, def->uuid)) == NULL)
        goto err;

    if (phypBuildStoragePool(conn, def) == -1)
        goto err;

    return sp;

  err:
    virStoragePoolDefFree(def);
    if (sp)
        virUnrefStoragePool(sp);
    return NULL;
}

static char *
phypGetStoragePoolXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    virCheckFlags(0, NULL);

    virStoragePoolDef def;
    memset(&def, 0, sizeof(virStoragePoolDef));

    if (pool->name != NULL)
        def.name = pool->name;
    else {
        VIR_ERROR0(_("Unable to determine storage pool's name."));
        goto err;
    }

    if (memmove(def.uuid, pool->uuid, VIR_UUID_BUFLEN) == NULL) {
        VIR_ERROR0(_("Unable to determine storage pool's uuid."));
        goto err;
    }

    if ((def.capacity =
         phypGetStoragePoolSize(pool->conn, pool->name)) == -1) {
        VIR_ERROR0(_("Unable to determine storage pools's size."));
        goto err;
    }

    /* Information not avaliable */
    def.allocation = 0;
    def.available = 0;

    def.source.ndevice = 1;

    /*XXX source adapter not working properly, should show hdiskX */
    if ((def.source.adapter =
         phypGetStoragePoolDevice(pool->conn, pool->name)) == NULL) {
        VIR_ERROR0(_("Unable to determine storage pools's source adapter."));
        goto err;
    }

    return virStoragePoolDefFormat(&def);

  err:
    return NULL;
}

static int
phypGetLparState(virConnectPtr conn, unsigned int lpar_id)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    char *char_ptr = NULL;
    char *managed_system = phyp_driver->managed_system;
    int state = VIR_DOMAIN_NOSTATE;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -F state --filter lpar_ids=%d", lpar_id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return state;
    }
    cmd = virBufferContentAndReset(&buf);

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

/* XXX - is this needed? */
static int phypDiskType(virConnectPtr, char *) ATTRIBUTE_UNUSED;
static int
phypDiskType(virConnectPtr conn, char *backing_device)
{
    phyp_driverPtr phyp_driver = conn->privateData;
    ConnectionData *connection_data = conn->networkPrivateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    char *char_ptr;
    char *managed_system = phyp_driver->managed_system;
    int vios_id = phyp_driver->vios_id;
    int disk_type = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "viosvrcmd");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -p %d -c \"lssp -field name type "
                      "-fmt , -all|sed -n '/%s/ {\n s/^.*,//\n p\n}'\"",
                      vios_id, backing_device);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return disk_type;
    }
    cmd = virBufferContentAndReset(&buf);

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
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    int got = 0;
    int i;
    char *cmd = NULL;
    char *ret = NULL;
    char *domains = NULL;
    char *char_ptr2 = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "lssyscfg -r lpar");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -F name,state"
                      "|sed -n '/Not Activated/ {\n s/,.*$//\n p\n}'");
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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
        VIR_ERROR0(_("Unable to determine domain's name."));
        goto err;
    }

    if (phypGetLparUUID(def.uuid, dom->id, dom->conn) == -1) {
        VIR_ERROR0(_("Unable to generate random uuid."));
        goto err;
    }

    if ((def.mem.max_balloon =
         phypGetLparMem(dom->conn, managed_system, dom->id, 0)) == 0) {
        VIR_ERROR0(_("Unable to determine domain's max memory."));
        goto err;
    }

    if ((def.mem.cur_balloon =
         phypGetLparMem(dom->conn, managed_system, dom->id, 1)) == 0) {
        VIR_ERROR0(_("Unable to determine domain's memory."));
        goto err;
    }

    if ((def.maxvcpus = def.vcpus =
         phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0) {
        VIR_ERROR0(_("Unable to determine domain's CPU."));
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
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "chsysstate");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r lpar -o on --id %d -f %s",
                      dom->id, dom->name);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

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
    virConnectPtr conn = dom->conn;
    LIBSSH2_SESSION *session = connection_data->session;
    phyp_driverPtr phyp_driver = conn->privateData;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "chsysstate");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r lpar -o shutdown --id %d", dom->id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return 0;
    }
    cmd = virBufferContentAndReset(&buf);

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
        VIR_WARN0("Unable to determine domain's max memory.");

    if ((info->memory =
         phypGetLparMem(dom->conn, managed_system, dom->id, 1)) == 0)
        VIR_WARN0("Unable to determine domain's memory.");

    if ((info->nrVirtCpu =
         phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0)
        VIR_WARN0("Unable to determine domain's CPU.");

    return 0;
}

static int
phypDomainDestroy(virDomainPtr dom)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "rmsyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r lpar --id %d", dom->id);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0)
        goto err;

    if (phypUUIDTable_RemLpar(dom->conn, dom->id) == -1)
        goto err;

    dom->id = -1;

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

  err:
    VIR_FREE(cmd);
    VIR_FREE(ret);
    return -1;

}

static int
phypBuildLpar(virConnectPtr conn, virDomainDefPtr def)
{
    ConnectionData *connection_data = conn->networkPrivateData;
    phyp_driverPtr phyp_driver = conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    char *cmd = NULL;
    char *ret = NULL;
    int exit_status = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!def->mem.cur_balloon) {
        PHYP_ERROR(VIR_ERR_XML_ERROR,"%s",
                _("Field \"<memory>\" on the domain XML file is missing or has "
                    "invalid value."));
        goto err;
    }

    if (!def->mem.max_balloon) {
        PHYP_ERROR(VIR_ERR_XML_ERROR,"%s",
                _("Field \"<currentMemory>\" on the domain XML file is missing or"
                    " has invalid value."));
        goto err;
    }

    if (def->ndisks < 1) {
        PHYP_ERROR(VIR_ERR_XML_ERROR, "%s",
                   _("Domain XML must contain at least one \"<disk>\" element."));
        goto err;
    }

    if (!def->disks[0]->src) {
        PHYP_ERROR(VIR_ERR_XML_ERROR,"%s",
                   _("Field \"<src>\" under \"<disk>\" on the domain XML file is "
                     "missing."));
        goto err;
    }

    virBufferAddLit(&buf, "mksyscfg");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " -r lpar -p %s -i min_mem=%d,desired_mem=%d,"
                      "max_mem=%d,desired_procs=%d,virtual_scsi_adapters=%s",
                      def->name, (int) def->mem.cur_balloon,
                      (int) def->mem.cur_balloon, (int) def->mem.max_balloon,
                      (int) def->vcpus, def->disks[0]->src);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, conn);

    if (exit_status < 0) {
        VIR_ERROR(_("Unable to create LPAR. Reason: '%s'"), ret);
        goto err;
    }

    if (phypUUIDTable_AddLpar(conn, def->uuid, def->id) == -1) {
        VIR_ERROR0(_("Unable to add LPAR to the table"));
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

static virDomainPtr
phypDomainCreateAndStart(virConnectPtr conn,
                         const char *xml, unsigned int flags)
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

    virCheckFlags(0, NULL);

    if (!(def = virDomainDefParseString(phyp_driver->caps, xml,
                                        VIR_DOMAIN_XML_SECURE)))
        goto err;

    /* checking if this name already exists on this system */
    if (phypGetLparID(session, managed_system, def->name, conn) != -1) {
        VIR_WARN0("LPAR name already exists.");
        goto err;
    }

    /* checking if ID or UUID already exists on this system */
    for (i = 0; i < uuid_table->nlpars; i++) {
        if (lpars[i]->id == def->id || lpars[i]->uuid == def->uuid) {
            VIR_WARN0("LPAR ID or UUID already exists.");
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

static int
phypDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                        unsigned int flags)
{
    ConnectionData *connection_data = dom->conn->networkPrivateData;
    phyp_driverPtr phyp_driver = dom->conn->privateData;
    LIBSSH2_SESSION *session = connection_data->session;
    int system_type = phyp_driver->system_type;
    char *managed_system = phyp_driver->managed_system;
    int exit_status = 0;
    char *cmd = NULL;
    char *ret = NULL;
    char operation;
    unsigned long ncpus = 0;
    unsigned int amount = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (flags != VIR_DOMAIN_VCPU_LIVE) {
        PHYP_ERROR(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    if ((ncpus = phypGetLparCPU(dom->conn, managed_system, dom->id)) == 0)
        return 0;

    if (nvcpus > phypGetLparCPUMAX(dom)) {
        VIR_ERROR0(_("You are trying to set a number of CPUs bigger than "
                     "the max possible."));
        return 0;
    }

    if (ncpus > nvcpus) {
        operation = 'r';
        amount = nvcpus - ncpus;
    } else if (ncpus < nvcpus) {
        operation = 'a';
        amount = nvcpus - ncpus;
    } else
        return 0;

    virBufferAddLit(&buf, "chhwres -r proc");
    if (system_type == HMC)
        virBufferVSprintf(&buf, " -m %s", managed_system);
    virBufferVSprintf(&buf, " --id %d -o %c --procunits %d 2>&1 |sed "
                      "-e 's/^.*\\([0-9][0-9]*.[0-9][0-9]*\\).*$/\\1/'",
                      dom->id, operation, amount);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return 0;
    }
    cmd = virBufferContentAndReset(&buf);

    ret = phypExec(session, cmd, &exit_status, dom->conn);

    if (exit_status < 0) {
        VIR_ERROR0(_
                   ("Possibly you don't have IBM Tools installed in your LPAR."
                    " Contact your support to enable this feature."));
    }

    VIR_FREE(cmd);
    VIR_FREE(ret);
    return 0;

}

static int
phypDomainSetCPU(virDomainPtr dom, unsigned int nvcpus)
{
    return phypDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_VCPU_LIVE);
}

static virDrvOpenStatus
phypVIOSDriverOpen(virConnectPtr conn,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   int flags ATTRIBUTE_UNUSED)
{
    if (conn->driver->no != VIR_DRV_PHYP)
        return VIR_DRV_OPEN_DECLINED;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
phypVIOSDriverClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static virDriver phypDriver = {
    VIR_DRV_PHYP, "PHYP", phypOpen,     /* open */
    phypClose,                  /* close */
    NULL,                       /* supports_feature */
    NULL,                       /* type */
    NULL,                       /* version */
    NULL,                       /* libvirtVersion (impl. in libvirt.c) */
    NULL,                       /* getHostname */
    NULL,                       /* getSysinfo */
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
    phypDomainSetVcpusFlags,    /* domainSetVcpusFlags */
    phypDomainGetVcpusFlags,    /* domainGetVcpusFlags */
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
    NULL,                       /* domainCreateWithFlags */
    NULL,                       /* domainDefineXML */
    NULL,                       /* domainUndefine */
    phypAttachDevice,           /* domainAttachDevice */
    NULL,                       /* domainAttachDeviceFlags */
    NULL,                       /* domainDetachDevice */
    NULL,                       /* domainDetachDeviceFlags */
    NULL,                       /* domainUpdateDeviceFlags */
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
    NULL,                       /* domainGetBlockInfo */
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
    phypIsEncrypted,            /* isEncrypted */
    phypIsSecure,               /* isSecure */
    NULL,                       /* domainIsActive */
    NULL,                       /* domainIsPersistent */
    phypIsUpdated,              /* domainIsUpdated */
    NULL,                       /* cpuCompare */
    NULL,                       /* cpuBaseline */
    NULL,                       /* domainGetJobInfo */
    NULL,                       /* domainAbortJob */
    NULL,                       /* domainMigrateSetMaxDowntime */
    NULL,                       /* domainEventRegisterAny */
    NULL,                       /* domainEventDeregisterAny */
    NULL,                       /* domainManagedSave */
    NULL,                       /* domainHasManagedSaveImage */
    NULL,                       /* domainManagedSaveRemove */
    NULL,                       /* domainSnapshotCreateXML */
    NULL,                       /* domainSnapshotDumpXML */
    NULL,                       /* domainSnapshotNum */
    NULL,                       /* domainSnapshotListNames */
    NULL,                       /* domainSnapshotLookupByName */
    NULL,                       /* domainHasCurrentSnapshot */
    NULL,                       /* domainSnapshotCurrent */
    NULL,                       /* domainRevertToSnapshot */
    NULL,                       /* domainSnapshotDelete */
    NULL,                       /* qemuMonitorCommand */
    NULL,                       /* domainSetMemoryParameters */
    NULL,                       /* domainGetMemoryParameters */
    NULL, /* domainOpenConsole */
};

static virStorageDriver phypStorageDriver = {
    .name = "PHYP",
    .open = phypVIOSDriverOpen,
    .close = phypVIOSDriverClose,

    .numOfPools = phypNumOfStoragePools,
    .listPools = phypListStoragePools,
    .numOfDefinedPools = NULL,
    .listDefinedPools = NULL,
    .findPoolSources = NULL,
    .poolLookupByName = phypStoragePoolLookupByName,
    .poolLookupByUUID = phypGetStoragePoolLookUpByUUID,
    .poolLookupByVolume = NULL,
    .poolCreateXML = phypStoragePoolCreateXML,
    .poolDefineXML = NULL,
    .poolBuild = NULL,
    .poolUndefine = NULL,
    .poolCreate = NULL,
    .poolDestroy = phypDestroyStoragePool,
    .poolDelete = NULL,
    .poolRefresh = NULL,
    .poolGetInfo = NULL,
    .poolGetXMLDesc = phypGetStoragePoolXMLDesc,
    .poolGetAutostart = NULL,
    .poolSetAutostart = NULL,
    .poolNumOfVolumes = phypStoragePoolNumOfVolumes,
    .poolListVolumes = phypStoragePoolListVolumes,

    .volLookupByName = phypVolumeLookupByName,
    .volLookupByKey = NULL,
    .volLookupByPath = phypVolumeLookupByPath,
    .volCreateXML = phypStorageVolCreateXML,
    .volCreateXMLFrom = NULL,
    .volDelete = NULL,
    .volGetInfo = NULL,
    .volGetXMLDesc = phypVolumeGetXMLDesc,
    .volGetPath = phypVolumeGetPath,
    .poolIsActive = NULL,
    .poolIsPersistent = NULL
};

static virNetworkDriver phypNetworkDriver = {
    .name = "PHYP",
    .open = phypVIOSDriverOpen,
    .close = phypVIOSDriverClose,
    .numOfNetworks = NULL,
    .listNetworks = NULL,
    .numOfDefinedNetworks = NULL,
    .listDefinedNetworks = NULL,
    .networkLookupByUUID = NULL,
    .networkLookupByName = NULL,
    .networkCreateXML = NULL,
    .networkDefineXML = NULL,
    .networkUndefine = NULL,
    .networkCreate = NULL,
    .networkDestroy = NULL,
    .networkDumpXML = NULL,
    .networkGetBridgeName = NULL,
    .networkGetAutostart = NULL,
    .networkSetAutostart = NULL,
    .networkIsActive = NULL,
    .networkIsPersistent = NULL
};

int
phypRegister(void)
{
    if (virRegisterDriver(&phypDriver) < 0)
        return -1;
    if (virRegisterStorageDriver(&phypStorageDriver) < 0)
        return -1;
    if (virRegisterNetworkDriver(&phypNetworkDriver) < 0)
        return -1;

    return 0;
}
