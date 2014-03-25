/*
 * openvz_conf.c: config functions for managing OpenVZ VEs
 *
 * Copyright (C) 2010-2012, 2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#include "virerror.h"
#include "openvz_conf.h"
#include "openvz_util.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "nodeinfo.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

static char *openvzLocateConfDir(void);
static int openvzGetVPSUUID(int vpsid, char *uuidstr, size_t len);
static int openvzAssignUUIDs(void);
static int openvzLocateConfFileDefault(int vpsid, char **conffile, const char *ext);

openvzLocateConfFileFunc openvzLocateConfFile = openvzLocateConfFileDefault;

int
strtoI(const char *str)
{
    int val;

    if (virStrToLong_i(str, NULL, 10, &val) < 0)
        return 0;

    return val;
}


static int
openvzExtractVersionInfo(const char *cmdstr, int *retversion)
{
    int ret = -1;
    unsigned long version;
    char *help = NULL;
    char *tmp;
    virCommandPtr cmd = virCommandNewArgList(cmdstr, "--help", NULL);

    if (retversion)
        *retversion = 0;

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    tmp = help;

    /* expected format: vzctl version <major>.<minor>.<micro> */
    if ((tmp = STRSKIP(tmp, "vzctl version ")) == NULL)
        goto cleanup;

    if (virParseVersionString(tmp, &version, true) < 0)
        goto cleanup;

    if (retversion)
        *retversion = version;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(help);

    return ret;
}

int openvzExtractVersion(struct openvz_driver *driver)
{
    if (driver->version > 0)
        return 0;

    if (openvzExtractVersionInfo(VZCTL, &driver->version) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not extract vzctl version"));
        return -1;
    }

    return 0;
}


/* Parse config values of the form barrier:limit into barrier and limit */
static int
openvzParseBarrierLimit(const char* value,
                        unsigned long long *barrier,
                        unsigned long long *limit)
{
    char *token;
    char *saveptr = NULL;
    char *str;
    int ret = -1;

    if (VIR_STRDUP(str, value) < 0)
        goto error;

    token = strtok_r(str, ":", &saveptr);
    if (token == NULL) {
        goto error;
    } else {
        if (barrier != NULL) {
            if (virStrToLong_ull(token, NULL, 10, barrier))
                goto error;
        }
    }
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
        goto error;
    } else {
        if (limit != NULL) {
            if (virStrToLong_ull(token, NULL, 10, limit))
                goto error;
        }
    }
    ret = 0;
 error:
    VIR_FREE(str);
    return ret;
}


virCapsPtr openvzCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   0, 0)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "exe",
                                         caps->host.arch,
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
    virObjectUnref(caps);
    return NULL;
}


int
openvzReadNetworkConf(virDomainDefPtr def,
                      int veid)
{
    int ret;
    virDomainNetDefPtr net = NULL;
    char *temp = NULL;
    char *token, *saveptr = NULL;

    /*parse routing network configuration*
     * Sample from config:
     *   IP_ADDRESS="1.1.1.1 1.1.1.2"
     *   splited IPs by space
     */
    ret = openvzReadVPSConfigParam(veid, "IP_ADDRESS", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'IP_ADDRESS' from config for container %d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        token = strtok_r(temp, " ", &saveptr);
        while (token != NULL) {
            if (VIR_ALLOC(net) < 0)
                goto error;

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            if (VIR_STRDUP(net->data.ethernet.ipaddr, token) < 0)
                goto error;

            if (VIR_APPEND_ELEMENT_COPY(def->nets, def->nnets, net) < 0)
                goto error;

            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    /*parse bridge devices*/
    /*Sample from config:
     *NETIF="ifname=eth10,mac=00:18:51:C1:05:EE,host_ifname=veth105.10,host_mac=00:18:51:8F:D9:F3"
     *devices splited by ';'
     */
    ret = openvzReadVPSConfigParam(veid, "NETIF", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'NETIF' from config for container %d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        token = strtok_r(temp, ";", &saveptr);
        while (token != NULL) {
            /*add new device to list*/
            if (VIR_ALLOC(net) < 0)
                goto error;

            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

            char *p = token;
            char cpy_temp[32];
            int len;

            /*parse string*/
            do {
                char *next = strchrnul(p, ',');
                if (STRPREFIX(p, "ifname=")) {
                    /* skip in libvirt */
                } else if (STRPREFIX(p, "host_ifname=")) {
                    p += 12;
                    len = next - p;
                    if (len > 16) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Too long network device name"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(net->ifname, len+1) < 0)
                        goto error;

                    if (virStrncpy(net->ifname, p, len, len+1) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Network ifname %s too long for destination"), p);
                        goto error;
                    }
                } else if (STRPREFIX(p, "bridge=")) {
                    p += 7;
                    len = next - p;
                    if (len > 16) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Too long bridge device name"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(net->data.bridge.brname, len+1) < 0)
                        goto error;

                    if (virStrncpy(net->data.bridge.brname, p, len, len+1) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Bridge name %s too long for destination"), p);
                        goto error;
                    }
                } else if (STRPREFIX(p, "mac=")) {
                    p += 4;
                    len = next - p;
                    if (len != 17) { /* should be 17 */
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Wrong length MAC address"));
                        goto error;
                    }
                    if (virStrncpy(cpy_temp, p, len, sizeof(cpy_temp)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("MAC address %s too long for destination"), p);
                        goto error;
                    }
                    if (virMacAddrParse(cpy_temp, &net->mac) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Wrong MAC address"));
                        goto error;
                    }
                }
                p = ++next;
            } while (p < token + strlen(token));

            if (VIR_APPEND_ELEMENT_COPY(def->nets, def->nnets, net) < 0)
                goto error;

            token = strtok_r(NULL, ";", &saveptr);
        }
    }

    VIR_FREE(temp);

    return 0;

 error:
    VIR_FREE(temp);
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
                 int veid)
{
    int ret;
    virDomainFSDefPtr fs = NULL;
    char *veid_str = NULL;
    char *temp = NULL;
    const char *param;
    unsigned long long barrier, limit;

    ret = openvzReadVPSConfigParam(veid, "OSTEMPLATE", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'OSTEMPLATE' from config for container %d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        if (VIR_ALLOC(fs) < 0)
            goto error;

        fs->type = VIR_DOMAIN_FS_TYPE_TEMPLATE;
        if (VIR_STRDUP(fs->src, temp) < 0)
            goto error;
    } else {
        /* OSTEMPLATE was not found, VE was booted from a private dir directly */
        ret = openvzReadVPSConfigParam(veid, "VE_PRIVATE", &temp);
        if (ret <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read 'VE_PRIVATE' from config for container %d"),
                           veid);
            goto error;
        }

        if (VIR_ALLOC(fs) < 0)
            goto error;

        if (virAsprintf(&veid_str, "%d", veid) < 0)
            goto error;

        fs->type = VIR_DOMAIN_FS_TYPE_MOUNT;
        if (!(fs->src = openvz_replace(temp, "$VEID", veid_str)))
            goto no_memory;

        VIR_FREE(veid_str);
    }

    if (VIR_STRDUP(fs->dst, "/") < 0)
        goto error;

    param = "DISKSPACE";
    ret = openvzReadVPSConfigParam(veid, param, &temp);
    if (ret > 0) {
        if (openvzParseBarrierLimit(temp, &barrier, &limit)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read '%s' from config for container %d"),
                           param, veid);
            goto error;
        } else {
            /* Ensure that we can multiply by 1024 without overflowing. */
            if (barrier > ULLONG_MAX / 1024 ||
                limit > ULLONG_MAX / 1024) {
                virReportSystemError(VIR_ERR_OVERFLOW, "%s",
                                     _("Unable to parse quota"));
                goto error;
            }
            fs->space_soft_limit = barrier * 1024; /* unit is bytes */
            fs->space_hard_limit = limit * 1024;   /* unit is bytes */
        }
    }

    if (VIR_APPEND_ELEMENT(def->fss, def->nfss, fs) < 0)
        goto error;

    VIR_FREE(temp);

    return 0;
 no_memory:
    virReportOOMError();
 error:
    VIR_FREE(temp);
    virDomainFSDefFree(fs);
    return -1;
}


static int
openvzReadMemConf(virDomainDefPtr def, int veid)
{
    int ret = -1;
    char *temp = NULL;
    unsigned long long barrier, limit;
    const char *param;
    long kb_per_pages;

    kb_per_pages = openvzKBPerPages();
    if (kb_per_pages < 0)
        goto error;

    /* Memory allocation guarantee */
    param = "VMGUARPAGES";
    ret = openvzReadVPSConfigParam(veid, param, &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read '%s' from config for container %d"),
                       param, veid);
        goto error;
    } else if (ret > 0) {
        ret = openvzParseBarrierLimit(temp, &barrier, NULL);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse barrier of '%s' "
                             "from config for container %d"), param, veid);
            goto error;
        }
        if (barrier == LONG_MAX)
            def->mem.min_guarantee = 0ull;
        else
            def->mem.min_guarantee = barrier * kb_per_pages;
    }

    /* Memory hard and soft limits */
    param = "PRIVVMPAGES";
    ret = openvzReadVPSConfigParam(veid, param, &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read '%s' from config for container %d"),
                       param, veid);
        goto error;
    } else if (ret > 0) {
        ret = openvzParseBarrierLimit(temp, &barrier, &limit);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse barrier and limit of '%s' "
                             "from config for container %d"), param, veid);
            goto error;
        }
        if (barrier == LONG_MAX)
            def->mem.soft_limit = 0ull;
        else
            def->mem.soft_limit = barrier * kb_per_pages;

        if (limit == LONG_MAX)
            def->mem.hard_limit = 0ull;
        else
            def->mem.hard_limit = limit * kb_per_pages;
    }

    ret = 0;
 error:
    VIR_FREE(temp);
    return ret;
}


/* Free all memory associated with a openvz_driver structure */
void
openvzFreeDriver(struct openvz_driver *driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->caps);
    VIR_FREE(driver);
}



int openvzLoadDomains(struct openvz_driver *driver)
{
    int veid, ret;
    char *status;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr dom = NULL;
    virDomainDefPtr def = NULL;
    char *temp = NULL;
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
        unsigned int flags = 0;
        if (virStrToLong_i(line, &status, 10, &veid) < 0 ||
            *status++ != ' ' ||
            (line = strchr(status, '\n')) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to parse vzlist output"));
            goto cleanup;
        }
        *line++ = '\0';

        if (VIR_ALLOC(def) < 0)
            goto cleanup;

        def->virtType = VIR_DOMAIN_VIRT_OPENVZ;

        if (STREQ(status, "stopped"))
            def->id = -1;
        else
            def->id = veid;
        if (virAsprintf(&def->name, "%i", veid) < 0)
            goto cleanup;

        openvzGetVPSUUID(veid, uuidstr, sizeof(uuidstr));
        ret = virUUIDParse(uuidstr, def->uuid);

        if (ret == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("UUID in config file malformed"));
            goto cleanup;
        }

        if (VIR_STRDUP(def->os.type, "exe") < 0)
            goto cleanup;
        if (VIR_STRDUP(def->os.init, "/sbin/init") < 0)
            goto cleanup;

        ret = openvzReadVPSConfigParam(veid, "CPUS", &temp);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read config for container %d"),
                           veid);
            goto cleanup;
        } else if (ret > 0) {
            def->maxvcpus = strtoI(temp);
        }

        if (ret == 0 || def->maxvcpus == 0)
            def->maxvcpus = openvzGetNodeCPUs();
        def->vcpus = def->maxvcpus;

        /* XXX load rest of VM config data .... */

        openvzReadNetworkConf(def, veid);
        openvzReadFSConf(def, veid);
        openvzReadMemConf(def, veid);

        virUUIDFormat(def->uuid, uuidstr);
        flags = VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE;
        if (STRNEQ(status, "stopped"))
            flags |= VIR_DOMAIN_OBJ_LIST_ADD_LIVE;

        if (!(dom = virDomainObjListAdd(driver->domains,
                                        def,
                                        driver->xmlopt,
                                        flags,
                                        NULL)))
            goto cleanup;

        if (STREQ(status, "stopped")) {
            virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_UNKNOWN);
            dom->pid = -1;
        } else {
            virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNKNOWN);
            dom->pid = veid;
        }
        /* XXX OpenVZ doesn't appear to have concept of a transient domain */
        dom->persistent = 1;

        virObjectUnlock(dom);
        dom = NULL;
        def = NULL;
    }

    virCommandFree(cmd);
    VIR_FREE(temp);
    VIR_FREE(outbuf);

    return 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(temp);
    VIR_FREE(outbuf);
    virObjectUnref(dom);
    virDomainDefFree(def);
    return -1;
}

unsigned int
openvzGetNodeCPUs(void)
{
    virNodeInfo nodeinfo;

    if (nodeGetInfo(&nodeinfo) < 0)
        return 0;

    return nodeinfo.cpus;
}

static int
openvzWriteConfigParam(const char * conf_file, const char *param, const char *value)
{
    char * temp_file = NULL;
    int temp_fd = -1;
    FILE *fp;
    char *line = NULL;
    size_t line_size = 0;

    if (virAsprintf(&temp_file, "%s.tmp", conf_file)<0)
        return -1;

    fp = fopen(conf_file, "r");
    if (fp == NULL)
        goto error;
    temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd == -1) {
        goto error;
    }

    while (1) {
        if (getline(&line, &line_size, fp) <= 0)
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

    if (VIR_FCLOSE(fp) < 0)
        goto error;
    if (VIR_CLOSE(temp_fd) < 0)
        goto error;

    if (rename(temp_file, conf_file) < 0)
        goto error;

    VIR_FREE(line);

    return 0;

 error:
    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
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

/*
 * value will be freed before a new value is assigned to it, the caller is
 * responsible for freeing it afterwards.
 *
 * Returns <0 on error, 0 if not found, 1 if found.
 */
int
openvzReadConfigParam(const char *conf_file, const char *param, char **value)
{
    char *line = NULL;
    size_t line_size = 0;
    FILE *fp;
    int err = 0;
    char *sf, *token, *saveptr = NULL;

    fp = fopen(conf_file, "r");
    if (fp == NULL)
        return -1;

    VIR_FREE(*value);
    while (1) {
        if (getline(&line, &line_size, fp) < 0) {
            err = !feof(fp);
            break;
        }

        if (! STREQLEN(line, param, strlen(param)))
            continue;

        sf = line + strlen(param);
        if (*sf++ != '=') continue;

        saveptr = NULL;
        if ((token = strtok_r(sf, "\"\t\n", &saveptr)) != NULL) {
            VIR_FREE(*value);
            if (VIR_STRDUP(*value, token) < 0) {
                err = 1;
                break;
            }
            /* keep going - last entry wins */
        }
    }
    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);

    return err ? -1 : *value ? 1 : 0;
}

/*
 * Read parameter from container config
 *
 * value will be freed before a new value is assined to it, the caller is
 * responsible for freeing it afterwards.
 *
 * sample: 133, "OSTEMPLATE", &value
 * return: -1 - error
 *          0 - don't found
 *          1 - OK
 */
int
openvzReadVPSConfigParam(int vpsid, const char *param, char **value)
{
    char *conf_file;
    int ret;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    ret = openvzReadConfigParam(conf_file, param, value);
    VIR_FREE(conf_file);
    return ret;
}

static int
openvz_copyfile(char* from_path, char* to_path)
{
    char *line = NULL;
    size_t line_size = 0;
    FILE *fp;
    int copy_fd;
    int bytes_read;

    fp = fopen(from_path, "r");
    if (fp == NULL)
        return -1;
    copy_fd = open(to_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (copy_fd == -1) {
        VIR_FORCE_FCLOSE(fp);
        return -1;
    }

    while (1) {
        if (getline(&line, &line_size, fp) <= 0)
            break;

        bytes_read = strlen(line);
        if (safewrite(copy_fd, line, bytes_read) != bytes_read)
            goto error;
    }

    if (VIR_FCLOSE(fp) < 0)
        goto error;
    if (VIR_CLOSE(copy_fd) < 0)
        goto error;

    VIR_FREE(line);

    return 0;

 error:
    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
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
    char *confdir = NULL;
    char *default_conf_file = NULL;
    char *configfile_value = NULL;
    char *conf_file = NULL;
    int ret = -1;

    if (openvzReadConfigParam(VZ_CONF_FILE, "CONFIGFILE", &configfile_value) < 0)
        goto cleanup;

    confdir = openvzLocateConfDir();
    if (confdir == NULL)
        goto cleanup;

    if (virAsprintf(&default_conf_file, "%s/ve-%s.conf-sample", confdir,
                    configfile_value) < 0)
        goto cleanup;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        goto cleanup;

    if (openvz_copyfile(default_conf_file, conf_file)<0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(confdir);
    VIR_FREE(default_conf_file);
    VIR_FREE(configfile_value);
    VIR_FREE(conf_file);
    return ret;
}

/* Locate config file of container
 * return -1 - error
 *         0 - OK */
static int
openvzLocateConfFileDefault(int vpsid, char **conffile, const char *ext)
{
    char *confdir;
    int ret = 0;

    confdir = openvzLocateConfDir();
    if (confdir == NULL)
        return -1;

    if (virAsprintf(conffile, "%s/%d.%s", confdir, vpsid,
                    ext ? ext : "conf") < 0)
        ret = -1;

    VIR_FREE(confdir);
    return ret;
}

static char *
openvzLocateConfDir(void)
{
    const char *conf_dir_list[] = {"/etc/vz/conf", "/usr/local/etc/conf", NULL};
    size_t i = 0;
    char *ret = NULL;

    while (conf_dir_list[i]) {
        if (virFileExists(conf_dir_list[i])) {
            ignore_value(VIR_STRDUP(ret, conf_dir_list[i]));
            goto cleanup;
        }
        i++;
    }

 cleanup:
    return ret;
}

/* Richard Steven's classic readline() function */
int
openvz_readline(int fd, char *ptr, int maxlen)
{
    int n, rc;
    char c;

    for (n = 1; n < maxlen; n++) {
        if ((rc = read(fd, &c, 1)) == 1) {
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
    char *line = NULL;
    size_t line_size = 0;
    char *saveptr = NULL;
    char *uuidbuf;
    char *iden;
    FILE *fp;
    int retval = -1;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    fp = fopen(conf_file, "r");
    if (fp == NULL)
        goto cleanup;

    while (1) {
        if (getline(&line, &line_size, fp) < 0) {
            if (feof(fp)) { /* EOF, UUID was not found */
                uuidstr[0] = 0;
                break;
            } else {
                goto cleanup;
            }
        }

        iden = strtok_r(line, " ", &saveptr);
        uuidbuf = strtok_r(NULL, "\n", &saveptr);

        if (iden != NULL && uuidbuf != NULL && STREQ(iden, "#UUID:")) {
            if (virStrcpy(uuidstr, uuidbuf, len) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid uuid %s"), uuidbuf);
                goto cleanup;
            }
            break;
        }
    }
    retval = 0;
 cleanup:
    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
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
openvzSetUUID(int vpsid)
{
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDGenerate(uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

int openvzGetVEID(const char *name)
{
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

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Failed to parse vzlist output"));
    return -1;
}
