/*
 * openvz_conf.c: config functions for managing OpenVZ VEs
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
 * Copyright (C) 2007 Anoop Joe Cyriac
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 * Shuveb Hussain <shuveb@binarykarma.com>
 * Anoop Joe Cyriac <anoop@binarykarma.com>
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "virterror_internal.h"
#include "openvz_conf.h"
#include "uuid.h"
#include "buf.h"
#include "memory.h"
#include "util.h"
#include "nodeinfo.h"
#include "files.h"
#include "command.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

static char *openvzLocateConfDir(void);
static int openvzGetVPSUUID(int vpsid, char *uuidstr, size_t len);
static int openvzLocateConfFile(int vpsid, char **conffile, const char *ext);
static int openvzAssignUUIDs(void);

int
strtoI(const char *str)
{
    int val;

    if (virStrToLong_i(str, NULL, 10, &val) < 0)
        return 0;

    return val;
}


static int
openvzExtractVersionInfo(const char *cmd, int *retversion)
{
    const char *const vzarg[] = { cmd, "--help", NULL };
    const char *const vzenv[] = { "LC_ALL=C", NULL };
    pid_t child;
    int newstdout = -1;
    int ret = -1, status;
    unsigned long version;
    char *tmp;

    if (retversion)
        *retversion = 0;

    if (virExec(vzarg, vzenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_NONE) < 0)
        return -1;

    char *help = NULL;
    int len = virFileReadLimFD(newstdout, 4096, &help);
    if (len < 0)
        goto cleanup2;

    tmp = help;

    /* expected format: vzctl version <major>.<minor>.<micro> */
    if ((tmp = STRSKIP(tmp, "vzctl version ")) == NULL)
        goto cleanup2;

    if (virParseVersionString(tmp, &version) < 0)
        goto cleanup2;

    if (retversion)
        *retversion = version;

    ret = 0;

cleanup2:
    VIR_FREE(help);
    if (VIR_CLOSE(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;
        ret = -1;
    }

    return ret;
}

int openvzExtractVersion(struct openvz_driver *driver)
{
    if (driver->version > 0)
        return 0;

    if (openvzExtractVersionInfo(VZCTL, &driver->version) < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Could not extract vzctl version"));
        return -1;
    }

    return 0;
}


virCapsPtr openvzCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x52, 0x54, 0x00 });

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "exe",
                                         utsname.machine,
                                         sizeof(int) == 4 ? 32 : 8,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "openvz",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;
    return caps;

no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}


static int
openvzReadNetworkConf(virDomainDefPtr def,
                      int veid) {
    int ret;
    virDomainNetDefPtr net = NULL;
    char temp[4096];
    char *token, *saveptr = NULL;

    /*parse routing network configuration*
     * Sample from config:
     *   IP_ADDRESS="1.1.1.1 1.1.1.2"
     *   splited IPs by space
     */
    ret = openvzReadVPSConfigParam(veid, "IP_ADDRESS", temp, sizeof(temp));
    if (ret < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not read 'IP_ADDRESS' from config for container %d"),
                    veid);
        goto error;
    } else if (ret > 0) {
        token = strtok_r(temp, " ", &saveptr);
        while (token != NULL) {
            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            net->data.ethernet.ipaddr = strdup(token);

            if (net->data.ethernet.ipaddr == NULL)
                goto no_memory;

            if (VIR_REALLOC_N(def->nets, def->nnets + 1) < 0)
                goto no_memory;
            def->nets[def->nnets++] = net;
            net = NULL;

            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    /*parse bridge devices*/
    /*Sample from config:
     *NETIF="ifname=eth10,mac=00:18:51:C1:05:EE,host_ifname=veth105.10,host_mac=00:18:51:8F:D9:F3"
     *devices splited by ';'
     */
    ret = openvzReadVPSConfigParam(veid, "NETIF", temp, sizeof(temp));
    if (ret < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not read 'NETIF' from config for container %d"),
                    veid);
        goto error;
    } else if (ret > 0) {
        token = strtok_r(temp, ";", &saveptr);
        while (token != NULL) {
            /*add new device to list*/
            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

            char *p = token;
            char cpy_temp[32];
            int len;

            /*parse string*/
            do {
                char *next = strchrnul (token, ',');
                if (STRPREFIX(p, "ifname=")) {
                    /* skip in libvirt */
                } else if (STRPREFIX(p, "host_ifname=")) {
                    p += 12;
                    len = next - p;
                    if (len > 16) {
                        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("Too long network device name"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(net->ifname, len+1) < 0)
                        goto no_memory;

                    if (virStrncpy(net->ifname, p, len, len+1) == NULL) {
                        openvzError(VIR_ERR_INTERNAL_ERROR,
                                    _("Network ifname %s too long for destination"), p);
                        goto error;
                    }
                } else if (STRPREFIX(p, "bridge=")) {
                    p += 7;
                    len = next - p;
                    if (len > 16) {
                        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("Too long bridge device name"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(net->data.bridge.brname, len+1) < 0)
                        goto no_memory;

                    if (virStrncpy(net->data.bridge.brname, p, len, len+1) == NULL) {
                        openvzError(VIR_ERR_INTERNAL_ERROR,
                                    _("Bridge name %s too long for destination"), p);
                        goto error;
                    }
                } else if (STRPREFIX(p, "mac=")) {
                    p += 4;
                    len = next - p;
                    if (len != 17) { /* should be 17 */
                        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("Wrong length MAC address"));
                        goto error;
                    }
                    if (virStrncpy(cpy_temp, p, len, sizeof(cpy_temp)) == NULL) {
                        openvzError(VIR_ERR_INTERNAL_ERROR,
                                    _("MAC address %s too long for destination"), p);
                        goto error;
                    }
                    if (virParseMacAddr(cpy_temp, net->mac) < 0) {
                        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("Wrong MAC address"));
                        goto error;
                    }
                }
                p = ++next;
            } while (p < token + strlen(token));

            if (VIR_REALLOC_N(def->nets, def->nnets + 1) < 0)
                goto no_memory;
            def->nets[def->nnets++] = net;
            net = NULL;

            token = strtok_r(NULL, ";", &saveptr);
        }
    }

    return 0;
no_memory:
    virReportOOMError();
error:
    virDomainNetDefFree(net);
    return -1;
}


/* utility function to replace 'from' by 'to' in 'str' */
static char*
openvz_replace(const char* str,
               const char* from,
               const char* to) {
    const char* offset = NULL;
    const char* str_start = str;
    int to_len;
    int from_len;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if ((!from) || (!to))
        return NULL;
    from_len = strlen(from);
    to_len = strlen(to);

    while ((offset = strstr(str_start, from)))
    {
        virBufferAdd(&buf, str_start, offset-str_start);
        virBufferAdd(&buf, to, to_len);
        str_start = offset + from_len;
    }

    virBufferAdd(&buf, str_start, -1);

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


static int
openvzReadFSConf(virDomainDefPtr def,
                 int veid) {
    int ret;
    virDomainFSDefPtr fs = NULL;
    char* veid_str = NULL;
    char temp[100];

    ret = openvzReadVPSConfigParam(veid, "OSTEMPLATE", temp, sizeof(temp));
    if (ret < 0) {
        openvzError(VIR_ERR_INTERNAL_ERROR,
                    _("Could not read 'OSTEMPLATE' from config for container %d"),
                    veid);
        goto error;
    } else if (ret > 0) {
        if (VIR_ALLOC(fs) < 0)
            goto no_memory;

        fs->type = VIR_DOMAIN_FS_TYPE_TEMPLATE;
        fs->src = strdup(temp);
    } else {
        /* OSTEMPLATE was not found, VE was booted from a private dir directly */
        ret = openvzReadVPSConfigParam(veid, "VE_PRIVATE", temp, sizeof(temp));
        if (ret <= 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("Could not read 'VE_PRIVATE' from config for container %d"),
                        veid);
            goto error;
        }

        if (VIR_ALLOC(fs) < 0)
            goto no_memory;

        if (virAsprintf(&veid_str, "%d", veid) < 0)
            goto no_memory;

        fs->type = VIR_DOMAIN_FS_TYPE_MOUNT;
        fs->src = openvz_replace(temp, "$VEID", veid_str);

        VIR_FREE(veid_str);
    }

    fs->dst = strdup("/");

    if (fs->src == NULL || fs->dst == NULL)
        goto no_memory;

    if (VIR_REALLOC_N(def->fss, def->nfss + 1) < 0)
        goto no_memory;
    def->fss[def->nfss++] = fs;
    fs = NULL;

    return 0;
no_memory:
    virReportOOMError();
error:
    virDomainFSDefFree(fs);
    return -1;
}


/* Free all memory associated with a openvz_driver structure */
void
openvzFreeDriver(struct openvz_driver *driver)
{
    if (!driver)
        return;

    virDomainObjListDeinit(&driver->domains);
    virCapabilitiesFree(driver->caps);
    VIR_FREE(driver);
}



int openvzLoadDomains(struct openvz_driver *driver) {
    int veid, ret;
    char *status;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr dom = NULL;
    char temp[50];
    char *outbuf = NULL;
    char *line;
    virCommandPtr cmd = NULL;

    if (openvzAssignUUIDs() < 0)
        return -1;

    cmd = virCommandNewArgList(VZLIST, "-a", "-ovpsid,status", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    line = outbuf;
    while (line[0] != '\0') {
        if (virStrToLong_i(line, &status, 10, &veid) < 0 ||
            *status++ != ' ' ||
            (line = strchr(status, '\n')) == NULL) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to parse vzlist output"));
            goto cleanup;
        }
        *line++ = '\0';

        if (VIR_ALLOC(dom) < 0)
            goto no_memory;

        if (virMutexInit(&dom->lock) < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot initialize mutex"));
            VIR_FREE(dom);
            goto cleanup;
        }

        virDomainObjLock(dom);

        if (VIR_ALLOC(dom->def) < 0)
            goto no_memory;

        if (STREQ(status, "stopped"))
            dom->state = VIR_DOMAIN_SHUTOFF;
        else
            dom->state = VIR_DOMAIN_RUNNING;

        dom->refs = 1;
        dom->pid = veid;
        dom->def->id = dom->state == VIR_DOMAIN_SHUTOFF ? -1 : veid;
        /* XXX OpenVZ doesn't appear to have concept of a transient domain */
        dom->persistent = 1;

        if (virAsprintf(&dom->def->name, "%i", veid) < 0)
            goto no_memory;

        openvzGetVPSUUID(veid, uuidstr, sizeof(uuidstr));
        ret = virUUIDParse(uuidstr, dom->def->uuid);

        if (ret == -1) {
            openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("UUID in config file malformed"));
            goto cleanup;
        }

        if (!(dom->def->os.type = strdup("exe")))
            goto no_memory;
        if (!(dom->def->os.init = strdup("/sbin/init")))
            goto no_memory;

        ret = openvzReadVPSConfigParam(veid, "CPUS", temp, sizeof(temp));
        if (ret < 0) {
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("Could not read config for container %d"),
                        veid);
            goto cleanup;
        } else if (ret > 0) {
            dom->def->maxvcpus = strtoI(temp);
        }

        if (ret == 0 || dom->def->maxvcpus == 0)
            dom->def->maxvcpus = openvzGetNodeCPUs();
        dom->def->vcpus = dom->def->maxvcpus;

        /* XXX load rest of VM config data .... */

        openvzReadNetworkConf(dom->def, veid);
        openvzReadFSConf(dom->def, veid);

        virUUIDFormat(dom->def->uuid, uuidstr);
        if (virHashAddEntry(driver->domains.objs, uuidstr, dom) < 0)
            goto no_memory;

        virDomainObjUnlock(dom);
        dom = NULL;
    }

    virCommandFree(cmd);
    VIR_FREE(outbuf);

    return 0;

 no_memory:
    virReportOOMError();

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    if (dom)
        virDomainObjUnref(dom);
    return -1;
}

unsigned int
openvzGetNodeCPUs(void)
{
    virNodeInfo nodeinfo;

    if (nodeGetInfo(NULL, &nodeinfo) < 0)
        return 0;

    return nodeinfo.cpus;
}

static int
openvzWriteConfigParam(const char * conf_file, const char *param, const char *value)
{
    char * temp_file = NULL;
    int fd = -1, temp_fd = -1;
    char line[PATH_MAX];

    if (virAsprintf(&temp_file, "%s.tmp", conf_file)<0) {
        virReportOOMError();
        return -1;
    }

    fd = open(conf_file, O_RDONLY);
    if (fd == -1)
        goto error;
    temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd == -1) {
        VIR_FORCE_CLOSE(fd);
        goto error;
    }

    while (1) {
        if (openvz_readline(fd, line, sizeof(line)) <= 0)
            break;

        if (!(STRPREFIX(line, param) && line[strlen(param)] == '=')) {
            if (safewrite(temp_fd, line, strlen(line)) !=
                strlen(line))
                goto error;
        }
    }

    if (safewrite(temp_fd, param, strlen(param)) < 0 ||
        safewrite(temp_fd, "=\"", 2) < 0 ||
        safewrite(temp_fd, value, strlen(value)) < 0 ||
        safewrite(temp_fd, "\"\n", 2) < 0)
        goto error;

    if (VIR_CLOSE(fd) < 0)
        goto error;
    if (VIR_CLOSE(temp_fd) < 0)
        goto error;

    if (rename(temp_file, conf_file) < 0)
        goto error;

    return 0;

error:
    VIR_FORCE_CLOSE(fd);
    VIR_FORCE_CLOSE(temp_fd);
    if (temp_file)
        unlink(temp_file);
    VIR_FREE(temp_file);
    return -1;
}

int
openvzWriteVPSConfigParam(int vpsid, const char *param, const char *value)
{
    char *conf_file;
    int ret;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    ret = openvzWriteConfigParam(conf_file, param, value);
    VIR_FREE(conf_file);
    return ret;
}

static int
openvzReadConfigParam(const char * conf_file ,const char * param, char *value, int maxlen)
{
    char line[PATH_MAX];
    int ret, found = 0;
    int fd;
    char * sf, * token;
    char *saveptr = NULL;

    value[0] = 0;

    fd = open(conf_file, O_RDONLY);
    if (fd == -1)
        return -1;

    while (1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if (ret <= 0)
            break;
        saveptr = NULL;
        if (STREQLEN(line, param, strlen(param))) {
            sf = line;
            sf += strlen(param);
            if (sf[0] == '=' && sf[1] != '\0' ) {
                sf++;
                if ((token = strtok_r(sf,"\"\t\n", &saveptr)) != NULL) {
                    if (virStrcpy(value, token, maxlen) == NULL) {
                        ret = -1;
                        break;
                    }
                    found = 1;
                }
            }
       }
    }
    VIR_FORCE_CLOSE(fd);

    if (ret == 0 && found)
        ret = 1;

    return ret;
}

/*
* Read parameter from container config
* sample: 133, "OSTEMPLATE", value, 1024
* return: -1 - error
*	   0 - don't found
*          1 - OK
*/
int
openvzReadVPSConfigParam(int vpsid ,const char * param, char *value, int maxlen)
{
    char *conf_file;
    int ret;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    ret = openvzReadConfigParam(conf_file, param, value, maxlen);
    VIR_FREE(conf_file);
    return ret;
}

static int
openvz_copyfile(char* from_path, char* to_path)
{
    char line[PATH_MAX];
    int fd, copy_fd;
    int bytes_read;

    fd = open(from_path, O_RDONLY);
    if (fd == -1)
        return -1;
    copy_fd = open(to_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (copy_fd == -1) {
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    while (1) {
        if (openvz_readline(fd, line, sizeof(line)) <= 0)
            break;

        bytes_read = strlen(line);
        if (safewrite(copy_fd, line, bytes_read) != bytes_read)
            goto error;
    }

    if (VIR_CLOSE(fd) < 0)
        goto error;
    if (VIR_CLOSE(copy_fd) < 0)
        goto error;

    return 0;

error:
    VIR_FORCE_CLOSE(fd);
    VIR_FORCE_CLOSE(copy_fd);
    return -1;
}

/*
* Copy the default config to the VE conf file
* return: -1 - error
*          0 - OK
*/
int
openvzCopyDefaultConfig(int vpsid)
{
    char * confdir = NULL;
    char * default_conf_file = NULL;
    char configfile_value[PATH_MAX];
    char *conf_file = NULL;
    int ret = -1;

    if (openvzReadConfigParam(VZ_CONF_FILE, "CONFIGFILE", configfile_value,
                              PATH_MAX) < 0)
        goto cleanup;

    confdir = openvzLocateConfDir();
    if (confdir == NULL)
        goto cleanup;

    if (virAsprintf(&default_conf_file, "%s/ve-%s.conf-sample", confdir,
                    configfile_value) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        goto cleanup;

    if (openvz_copyfile(default_conf_file, conf_file)<0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(confdir);
    VIR_FREE(default_conf_file);
    VIR_FREE(conf_file);
    return ret;
}

/* Locate config file of container
* return -1 - error
*         0 - OK
*/
static int
openvzLocateConfFile(int vpsid, char **conffile, const char *ext)
{
    char * confdir;
    int ret = 0;

    confdir = openvzLocateConfDir();
    if (confdir == NULL)
        return -1;

    if (virAsprintf(conffile, "%s/%d.%s", confdir, vpsid,
                    ext ? ext : "conf") < 0) {
        virReportOOMError();
        ret = -1;
    }

    VIR_FREE(confdir);
    return ret;
}

static char
*openvzLocateConfDir(void)
{
    const char *conf_dir_list[] = {"/etc/vz/conf", "/usr/local/etc/conf", NULL};
    int i=0;

    while (conf_dir_list[i]) {
        if (!access(conf_dir_list[i], F_OK))
            return strdup(conf_dir_list[i]);
        i++;
    }

    return NULL;
}

/* Richard Steven's classic readline() function */
int
openvz_readline(int fd, char *ptr, int maxlen)
{
    int n, rc;
    char c;

    for (n = 1; n < maxlen; n++) {
        if ( (rc = read(fd, &c, 1)) == 1) {
            *ptr++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0; /* EOF condition */
            else
                break;
        }
        else
            return -1; /* error */
    }
    *ptr = 0;
    return n;
}

static int
openvzGetVPSUUID(int vpsid, char *uuidstr, size_t len)
{
    char *conf_file;
    char line[1024];
    char *saveptr = NULL;
    char *uuidbuf;
    char *iden;
    int fd, ret;
    int retval = -1;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    fd = open(conf_file, O_RDONLY);
    if (fd == -1)
        goto cleanup;

    while (1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if (ret == -1)
            goto cleanup;

        if (ret == 0) { /* EoF, UUID was not found */
            uuidstr[0] = 0;
            break;
        }

        iden = strtok_r(line, " ", &saveptr);
        uuidbuf = strtok_r(NULL, "\n", &saveptr);

        if (iden != NULL && uuidbuf != NULL && STREQ(iden, "#UUID:")) {
            if (virStrcpy(uuidstr, uuidbuf, len) == NULL) {
                openvzError(VIR_ERR_INTERNAL_ERROR,
                            _("invalid uuid %s"), uuidbuf);
                goto cleanup;
            }
            break;
        }
    }
    retval = 0;
cleanup:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(conf_file);

    return retval;
}

/* Do actual checking for UUID presence in conf file,
 * assign if not present.
 */
int
openvzSetDefinedUUID(int vpsid, unsigned char *uuid)
{
    char *conf_file;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    FILE *fp = NULL;
    int ret = -1;

    if (uuid == NULL)
        return -1;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    if (openvzGetVPSUUID(vpsid, uuidstr, sizeof(uuidstr)))
        goto cleanup;

    if (uuidstr[0] == 0) {
        fp = fopen(conf_file, "a"); /* append */
        if (fp == NULL)
            goto cleanup;

        virUUIDFormat(uuid, uuidstr);

        /* Record failure if fprintf or VIR_FCLOSE fails,
           and be careful always to close the stream.  */
        if ((fprintf(fp, "\n#UUID: %s\n", uuidstr) < 0) ||
            (VIR_FCLOSE(fp) == EOF))
            goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FORCE_FCLOSE(fp);
    VIR_FREE(conf_file);
    return ret;
}

static int
openvzSetUUID(int vpsid){
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDGenerate(uuid)) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to generate UUID"));
        return -1;
    }

    return openvzSetDefinedUUID(vpsid, uuid);
}

/*
 * Scan VPS config files and see if they have a UUID.
 * If not, assign one. Just append one to the config
 * file as comment so that the OpenVZ tools ignore it.
 *
 */

static int openvzAssignUUIDs(void)
{
    DIR *dp;
    struct dirent *dent;
    char *conf_dir;
    int vpsid;
    char *ext;
    int ret = 0;

    conf_dir = openvzLocateConfDir();
    if (conf_dir == NULL)
        return -1;

    dp = opendir(conf_dir);
    if (dp == NULL) {
        VIR_FREE(conf_dir);
        return 0;
    }

    errno = 0;
    while ((dent = readdir(dp))) {
        if (virStrToLong_i(dent->d_name, &ext, 10, &vpsid) < 0 ||
            *ext++ != '.' ||
            STRNEQ(ext, "conf"))
            continue;
        if (vpsid > 0) /* '0.conf' belongs to the host, ignore it */
            openvzSetUUID(vpsid);
        errno = 0;
    }
    if (errno) {
        openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to scan configuration directory"));
        ret = -1;
    }

    closedir(dp);
    VIR_FREE(conf_dir);
    return ret;
}


/*
 * Return CTID from name
 *
 */

int openvzGetVEID(const char *name) {
    virCommandPtr cmd;
    char *outbuf;
    char *temp;
    int veid;
    bool ok;

    cmd = virCommandNewArgList(VZLIST, name, "-ovpsid", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0) {
        virCommandFree(cmd);
        VIR_FREE(outbuf);
        return -1;
    }

    virCommandFree(cmd);
    ok = virStrToLong_i(outbuf, &temp, 10, &veid) == 0 && *temp == '\n';
    VIR_FREE(outbuf);

    if (ok && veid >= 0)
        return veid;

    openvzError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Failed to parse vzlist output"));
    return -1;
}
