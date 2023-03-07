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
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>

#include "virerror.h"
#include "openvz_conf.h"
#include "openvz_util.h"
#include "viruuid.h"
#include "viralloc.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"
#include "virhostcpu.h"

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
    unsigned long long version;
    g_autofree char *help = NULL;
    char *tmp;
    g_autoptr(virCommand) cmd = virCommandNewArgList(cmdstr, "--help", NULL);

    if (retversion)
        *retversion = 0;

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    tmp = help;

    /* expected format: vzctl version <major>.<minor>.<micro> */
    if ((tmp = STRSKIP(tmp, "vzctl version ")) == NULL)
        return -1;

    if (virStringParseVersion(&version, tmp, true) < 0)
        return -1;

    if (retversion)
        *retversion = version;

    return 0;
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
    g_auto(GStrv) tmp = NULL;

    if (!(tmp = g_strsplit(value, ":", 0)))
        return -1;

    if (g_strv_length(tmp) != 2)
        return -1;

    if (barrier && virStrToLong_ull(tmp[0], NULL, 10, barrier) < 0)
        return -1;

    if (limit && virStrToLong_ull(tmp[1], NULL, 10, limit) < 0)
        return -1;

    return 0;
}


virCaps *openvzCapsInit(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        return NULL;

    if (virCapabilitiesInitCaches(caps) < 0)
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                    caps->host.arch, NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_OPENVZ,
                                  NULL, NULL, 0, NULL);

    return g_steal_pointer(&caps);
}


int
openvzReadNetworkConf(virDomainDef *def,
                      int veid)
{
    int ret;
    virDomainNetDef *net = NULL;
    char *temp = NULL;
    char *token, *saveptr = NULL;

    /*parse routing network configuration*
     * Sample from config:
     *   IP_ADDRESS="1.1.1.1 1.1.1.2"
     * IPs split by space
     */
    ret = openvzReadVPSConfigParam(veid, "IP_ADDRESS", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'IP_ADDRESS' from config for container %1$d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        token = strtok_r(temp, " ", &saveptr);
        while (token != NULL) {
            net = g_new0(virDomainNetDef, 1);

            net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            if (virDomainNetAppendIPAddress(net, token, AF_UNSPEC, 0) < 0)
                goto error;

            VIR_APPEND_ELEMENT_COPY(def->nets, def->nnets, net);

            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    /*parse bridge devices*/
    /*Sample from config:
     * NETIF="ifname=eth10,mac=00:18:51:C1:05:EE,host_ifname=veth105.10,host_mac=00:18:51:8F:D9:F3"
     *devices split by ';'
     */
    ret = openvzReadVPSConfigParam(veid, "NETIF", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'NETIF' from config for container %1$d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        g_auto(GStrv) devices = g_strsplit(temp, ";", 0);
        GStrv device;

        for (device = devices; device && *device; device++) {
            g_auto(GStrv) keyvals = g_strsplit(*device, ",", 0);
            GStrv keyval;

            net = g_new0(virDomainNetDef, 1);
            net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

            for (keyval = keyvals; keyval && *keyval; keyval++) {
                char *val = strchr(*keyval, '=');

                if (!val)
                    continue;

                val++;

                if (STRPREFIX(*keyval, "ifname=")) {
                    /* skip in libvirt */
                } else if (STRPREFIX(*keyval, "host_ifname=")) {
                    if (strlen(val) > 16) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Too long network device name"));
                        goto error;
                    }

                    net->ifname = g_strdup(val);
                } else if (STRPREFIX(*keyval, "bridge=")) {
                    if (strlen(val) > 16) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Too long bridge device name"));
                        goto error;
                    }

                    net->data.bridge.brname = g_strdup(val);
                } else if (STRPREFIX(*keyval, "mac=")) {
                    if (strlen(val) != 17) { /* should be 17 */
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Wrong length MAC address"));
                        goto error;
                    }
                    if (virMacAddrParse(val, &net->mac) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Wrong MAC address"));
                        goto error;
                    }
                }
            }

            VIR_APPEND_ELEMENT_COPY(def->nets, def->nnets, net);
        }
    }

    VIR_FREE(temp);

    return 0;

 error:
    VIR_FREE(temp);
    virDomainNetDefFree(net);
    return -1;
}


static int
openvzReadFSConf(virDomainDef *def,
                 int veid)
{
    int ret;
    virDomainFSDef *fs = NULL;
    g_autofree char *veid_str = NULL;
    char *temp = NULL;
    const char *param;
    unsigned long long barrier, limit;

    ret = openvzReadVPSConfigParam(veid, "OSTEMPLATE", &temp);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not read 'OSTEMPLATE' from config for container %1$d"),
                       veid);
        goto error;
    } else if (ret > 0) {
        if (!(fs = virDomainFSDefNew(NULL)))
            goto error;

        fs->type = VIR_DOMAIN_FS_TYPE_TEMPLATE;
        fs->src->path = g_strdup(temp);
    } else {
        /* OSTEMPLATE was not found, VE was booted from a private dir directly */
        ret = openvzReadVPSConfigParam(veid, "VE_PRIVATE", &temp);
        if (ret <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read 'VE_PRIVATE' from config for container %1$d"),
                           veid);
            goto error;
        }

        if (!(fs = virDomainFSDefNew(NULL)))
            goto error;

        veid_str = g_strdup_printf("%d", veid);

        fs->type = VIR_DOMAIN_FS_TYPE_MOUNT;
        if (!(fs->src->path = virStringReplace(temp, "$VEID", veid_str)))
            goto error;
    }

    fs->dst = g_strdup("/");

    param = "DISKSPACE";
    ret = openvzReadVPSConfigParam(veid, param, &temp);
    if (ret > 0) {
        if (openvzParseBarrierLimit(temp, &barrier, &limit)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read '%1$s' from config for container %2$d"),
                           param, veid);
            goto error;
        } else {
            /* Ensure that we can multiply by 1024 without overflowing. */
            if (barrier > ULLONG_MAX / 1024 ||
                limit > ULLONG_MAX / 1024) {
                virReportError(VIR_ERR_OVERFLOW, "%s",
                               _("Unable to parse quota"));
                goto error;
            }
            fs->space_soft_limit = barrier * 1024; /* unit is bytes */
            fs->space_hard_limit = limit * 1024;   /* unit is bytes */
        }
    }

    VIR_APPEND_ELEMENT(def->fss, def->nfss, fs);

    VIR_FREE(temp);

    return 0;
 error:
    VIR_FREE(temp);
    virDomainFSDefFree(fs);
    return -1;
}


static int
openvzReadMemConf(virDomainDef *def, int veid)
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
                       _("Could not read '%1$s' from config for container %2$d"),
                       param, veid);
        goto error;
    } else if (ret > 0) {
        ret = openvzParseBarrierLimit(temp, &barrier, NULL);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse barrier of '%1$s' from config for container %2$d"),
                           param, veid);
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
                       _("Could not read '%1$s' from config for container %2$d"),
                       param, veid);
        goto error;
    } else if (ret > 0) {
        ret = openvzParseBarrierLimit(temp, &barrier, &limit);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse barrier and limit of '%1$s' from config for container %2$d"),
                           param, veid);
            goto error;
        }
        if (barrier == LONG_MAX)
            def->mem.soft_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        else
            def->mem.soft_limit = barrier * kb_per_pages;

        if (limit == LONG_MAX)
            def->mem.hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
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
    g_free(driver);
}



int openvzLoadDomains(struct openvz_driver *driver)
{
    int veid, ret;
    char *status;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObj *dom = NULL;
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *temp = NULL;
    g_autofree char *outbuf = NULL;
    char *line;
    g_autoptr(virCommand) cmd = NULL;
    unsigned int vcpus = 0;

    if (openvzAssignUUIDs() < 0)
        return -1;

    cmd = virCommandNewArgList(VZLIST, "-a", "-ovpsid,status", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    line = outbuf;
    while (line[0] != '\0') {
        unsigned int flags = 0;
        if (virStrToLong_i(line, &status, 10, &veid) < 0 ||
            *status++ != ' ' ||
            (line = strchr(status, '\n')) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to parse vzlist output"));
            return -1;
        }
        *line++ = '\0';

        if (!(def = virDomainDefNew(driver->xmlopt)))
            return -1;

        def->virtType = VIR_DOMAIN_VIRT_OPENVZ;

        if (STREQ(status, "stopped"))
            def->id = -1;
        else
            def->id = veid;
        def->name = g_strdup_printf("%i", veid);

        openvzGetVPSUUID(veid, uuidstr, sizeof(uuidstr));
        ret = virUUIDParse(uuidstr, def->uuid);

        if (ret == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("UUID in config file malformed"));
            return -1;
        }

        def->os.type = VIR_DOMAIN_OSTYPE_EXE;
        def->os.init = g_strdup("/sbin/init");

        ret = openvzReadVPSConfigParam(veid, "CPUS", &temp);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read config for container %1$d"),
                           veid);
            return -1;
        } else if (ret > 0) {
            vcpus = strtoI(temp);
        }

        if (ret == 0 || vcpus == 0)
            vcpus = virHostCPUGetCount();

        if (virDomainDefSetVcpusMax(def, vcpus, driver->xmlopt) < 0)
            return -1;

        if (virDomainDefSetVcpus(def, vcpus) < 0)
            return -1;

        /* XXX load rest of VM config data .... */

        openvzReadNetworkConf(def, veid);
        openvzReadFSConf(def, veid);
        openvzReadMemConf(def, veid);

        virUUIDFormat(def->uuid, uuidstr);
        flags = VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE;
        if (STRNEQ(status, "stopped"))
            flags |= VIR_DOMAIN_OBJ_LIST_ADD_LIVE;

        if (!(dom = virDomainObjListAdd(driver->domains,
                                        &def,
                                        driver->xmlopt,
                                        flags,
                                        NULL)))
            return -1;

        if (STREQ(status, "stopped")) {
            virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_UNKNOWN);
            dom->pid = 0;
        } else {
            virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNKNOWN);
            dom->pid = veid;
        }
        /* XXX OpenVZ doesn't appear to have concept of a transient domain */
        dom->persistent = 1;

        virDomainObjEndAPI(&dom);
        dom = NULL;
    }

    return 0;
}

static int
openvzWriteConfigParam(const char * conf_file, const char *param, const char *value)
{
    g_autofree char *temp_file = NULL;
    int temp_fd = -1;
    FILE *fp;
    char *line = NULL;
    size_t line_size = 0;

    temp_file = g_strdup_printf("%s.tmp", conf_file);

    fp = fopen(conf_file, "r");
    if (fp == NULL)
        goto error;
    temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd == -1)
        goto error;

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

        if (!(sf = STRSKIP(line, param)))
            continue;

        if (*sf++ != '=')
            continue;

        saveptr = NULL;
        if ((token = strtok_r(sf, "\"\t\n", &saveptr)) != NULL) {
            VIR_FREE(*value);
            *value = g_strdup(token);
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
 * value will be freed before a new value is assigned to it, the caller is
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

    default_conf_file = g_strdup_printf("%s/ve-%s.conf-sample", confdir,
                                        configfile_value);

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

    *conffile = g_strdup_printf("%s/%d.%s", confdir, vpsid, ext ? ext : "conf");

    VIR_FREE(confdir);
    return ret;
}

static char *
openvzLocateConfDir(void)
{
    const char *conf_dir_list[] = {"/etc/vz/conf", "/usr/local/etc/conf", NULL};
    size_t i = 0;

    while (conf_dir_list[i]) {
        if (virFileExists(conf_dir_list[i]))
            return g_strdup(conf_dir_list[i]);

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
            if (virStrcpy(uuidstr, uuidbuf, len) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid uuid %1$s"), uuidbuf);
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

    if (virUUIDGenerate(uuid) < 0) {
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
    g_autoptr(DIR) dp = NULL;
    struct dirent *dent;
    char *conf_dir;
    int vpsid;
    char *ext;
    int ret = 0;

    conf_dir = openvzLocateConfDir();
    if (conf_dir == NULL)
        return -1;

    if (virDirOpenQuiet(&dp, conf_dir) < 0) {
        VIR_FREE(conf_dir);
        return 0;
    }

    while ((ret = virDirRead(dp, &dent, conf_dir)) > 0) {
        if (virStrToLong_i(dent->d_name, &ext, 10, &vpsid) < 0 ||
            *ext++ != '.' ||
            STRNEQ(ext, "conf"))
            continue;
        if (vpsid > 0) /* '0.conf' belongs to the host, ignore it */
            openvzSetUUID(vpsid);
    }

    VIR_FREE(conf_dir);
    return ret;
}


/*
 * Return CTID from name
 *
 */

int openvzGetVEID(const char *name)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *outbuf = NULL;
    char *temp;
    int veid;
    bool ok;

    cmd = virCommandNewArgList(VZLIST, name, "-ovpsid", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    ok = virStrToLong_i(outbuf, &temp, 10, &veid) == 0 && *temp == '\n';

    if (ok && veid >= 0)
        return veid;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Failed to parse vzlist output"));
    return -1;
}


static int
openvzDomainDefPostParse(virDomainDef *def,
                         unsigned int parseFlags G_GNUC_UNUSED,
                         void *opaque,
                         void *parseOpaque G_GNUC_UNUSED)
{
    struct openvz_driver *driver = opaque;
    if (!virCapabilitiesDomainSupported(driver->caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    /* fill the init path */
    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE && !def->os.init)
        def->os.init = g_strdup("/sbin/init");

    return 0;
}


static int
openvzDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                               const virDomainDef *def G_GNUC_UNUSED,
                               unsigned int parseFlags G_GNUC_UNUSED,
                               void *opaque G_GNUC_UNUSED,
                               void *parseOpaque G_GNUC_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ;

    /* forbid capabilities mode hostdev in this kind of hypervisor */
    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not supported in %1$s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO &&
        dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM)
            dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_VGA;
        else
            dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_PARALLELS;
    }

    return 0;
}


virDomainDefParserConfig openvzDomainDefParserConfig = {
    .domainPostParseCallback = openvzDomainDefPostParse,
    .devicesPostParseCallback = openvzDomainDeviceDefPostParse,
    .features = VIR_DOMAIN_DEF_FEATURE_NAME_SLASH,
};

virDomainXMLOption *openvzXMLOption(struct openvz_driver *driver)
{
    openvzDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&openvzDomainDefParserConfig,
                                 NULL, NULL, NULL, NULL, NULL);
}
