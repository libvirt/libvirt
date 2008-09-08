/*
 * openvz_conf.c: config functions for managing OpenVZ VEs
 *
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
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>

#include "openvz_conf.h"
#include "uuid.h"
#include "buf.h"
#include "memory.h"
#include "util.h"

static char *openvzLocateConfDir(void);
static int openvzGetVPSUUID(int vpsid, char *uuidstr);
static int openvzLocateConfFile(int vpsid, char *conffile, int maxlen);
static int openvzAssignUUIDs(void);

void
openvzError (virConnectPtr conn, virErrorNumber code, const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];
    const char *errmsg;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    errmsg = __virErrorMsg(code, (errorMessage[0] ? errorMessage : NULL));
    __virRaiseError (conn, NULL, NULL, VIR_FROM_OPENVZ,
                     code, VIR_ERR_ERROR, errmsg, errorMessage, NULL, 0, 0,
                     errmsg, errorMessage);
}


int
strtoI(const char *str)
{
    int val;

    if (virStrToLong_i(str, NULL, 10, &val) < 0)
        return 0 ;

    return val;
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


/* function checks MAC address is empty
   return 0 - empty
          1 - not
*/
int openvzCheckEmptyMac(const unsigned char *mac)
{
    int i;
    for (i = 0; i < VIR_DOMAIN_NET_MAC_SIZE; i++)
        if (mac[i] != 0x00)
            return 1;

    return 0;
}

/* convert mac address to string
   return pointer to string or NULL
*/
char *openvzMacToString(const unsigned char *mac)
{
    char str[20];
    if (snprintf(str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac[0], mac[1], mac[2],
                      mac[3], mac[4], mac[5]) >= 18)
        return NULL;

    return strdup(str);
}

/* Free all memory associated with a openvz_driver structure */
void
openvzFreeDriver(struct openvz_driver *driver)
{
    virDomainObjPtr dom;

    if (!driver)
        return;

    dom = driver->domains;
    while (dom) {
        virDomainObjPtr tmp = dom->next;
        virDomainObjFree(dom);
        dom = tmp;
    }

    virCapabilitiesFree(driver->caps);
}



int openvzLoadDomains(struct openvz_driver *driver) {
    FILE *fp;
    int veid, ret;
    char status[16];
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr dom = NULL, prev = NULL;
    char temp[50];

    if (openvzAssignUUIDs() < 0)
        return -1;

    if ((fp = popen(VZLIST " -a -ovpsid,status -H 2>/dev/null", "r")) == NULL) {
        openvzError(NULL, VIR_ERR_INTERNAL_ERROR, _("popen failed"));
        return -1;
    }

    while(!feof(fp)) {
        if (fscanf(fp, "%d %s\n", &veid, status) != 2) {
            if (feof(fp))
                break;

            openvzError(NULL, VIR_ERR_INTERNAL_ERROR,
                        _("Failed to parse vzlist output"));
            goto cleanup;
        }

        if (VIR_ALLOC(dom) < 0 ||
            VIR_ALLOC(dom->def) < 0)
            goto no_memory;

        if (STREQ(status, "stopped"))
            dom->state = VIR_DOMAIN_SHUTOFF;
        else
            dom->state = VIR_DOMAIN_RUNNING;

        dom->pid = veid;
        dom->def->id = dom->state == VIR_DOMAIN_SHUTOFF ? -1 : veid;

        if (asprintf(&dom->def->name, "%i", veid) < 0) {
            dom->def->name = NULL;
            goto no_memory;
        }

        openvzGetVPSUUID(veid, uuidstr);
        ret = virUUIDParse(uuidstr, dom->def->uuid);

        if (ret == -1) {
            openvzError(NULL, VIR_ERR_INTERNAL_ERROR,
                        _("UUID in config file malformed"));
            goto cleanup;
        }

        if (!(dom->def->os.type = strdup("exe")))
            goto no_memory;
        if (!(dom->def->os.init = strdup("/sbin/init")))
            goto no_memory;

        ret = openvzReadConfigParam(veid, "CPUS", temp, sizeof(temp));
        if (ret < 0) {
            openvzError(NULL, VIR_ERR_INTERNAL_ERROR,
                        _("Cound not read config for container %d"),
                        veid);
            goto cleanup;
        } else if (ret > 0) {
            dom->def->vcpus = strtoI(temp);
        } else {
            dom->def->vcpus = 1;
        }

        /* XXX load rest of VM config data .... */

        if (prev) {
            prev->next = dom;
        } else {
            driver->domains = dom;
        }
        prev = dom;
    }

    fclose(fp);

    return 0;

 no_memory:
    openvzError(NULL, VIR_ERR_NO_MEMORY, NULL);

 cleanup:
    fclose(fp);
    virDomainObjFree(dom);
    return -1;
}

/*
* Read parameter from container config
* sample: 133, "OSTEMPLATE", value, 1024
* return: -1 - error
*	   0 - don't found
*          1 - OK
*/
int
openvzReadConfigParam(int vpsid ,const char * param, char *value, int maxlen)
{
    char conf_file[PATH_MAX] ;
    char line[PATH_MAX] ;
    int ret, found = 0;
    int fd ;
    char * sf, * token;
    char *saveptr = NULL;

    if (openvzLocateConfFile(vpsid, conf_file, PATH_MAX)<0)
        return -1;

    value[0] = 0;

    fd = open(conf_file, O_RDONLY);
    if (fd == -1)
        return -1;

    while(1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if(ret <= 0)
            break;
        saveptr = NULL;
        if (STREQLEN(line, param, strlen(param))) {
            sf = line;
            sf += strlen(param);
            if (sf[0] == '=' && sf[1] != '\0' ) {
                sf ++;
                if ((token = strtok_r(sf,"\"\t\n", &saveptr)) != NULL) {
                    strncpy(value, token, maxlen) ;
                    value[maxlen-1] = '\0';
                    found = 1;
                }
            }
       }
    }
    close(fd);

    if (ret == 0 && found)
        ret = 1;

    return ret ;
}

/* Locate config file of container
* return -1 - error
*         0 - OK
*/
static int
openvzLocateConfFile(int vpsid, char *conffile, int maxlen)
{
    char * confdir;
    int ret = 0;

    confdir = openvzLocateConfDir();
    if (confdir == NULL)
        return -1;

    if (snprintf(conffile, maxlen, "%s/%d.conf", confdir, vpsid) >= maxlen)
        ret = -1;

    VIR_FREE(confdir);
    return ret;
}

static char
*openvzLocateConfDir(void)
{
    const char *conf_dir_list[] = {"/etc/vz/conf", "/usr/local/etc/conf", NULL};
    int i=0;

    while(conf_dir_list[i]) {
        if(!access(conf_dir_list[i], F_OK))
            return strdup(conf_dir_list[i]);
        i ++;
    }

    return NULL;
}

/* Richard Steven's classic readline() function */
int
openvz_readline(int fd, char *ptr, int maxlen)
{
    int n, rc;
    char c;

    for(n = 1; n < maxlen; n ++) {
        if( (rc = read(fd, &c, 1)) == 1) {
            *ptr++ = c;
            if(c == '\n')
                break;
        }
        else if(rc == 0) {
            if(n == 1)
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
openvzGetVPSUUID(int vpsid, char *uuidstr)
{
    char conf_file[PATH_MAX];
    char line[1024];
    char uuidbuf[1024];
    char iden[1024];
    int fd, ret;

   if (openvzLocateConfFile(vpsid, conf_file, PATH_MAX)<0)
       return -1;

    fd = open(conf_file, O_RDONLY);
    if(fd == -1)
        return -1;

    while(1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if(ret == -1)
            return -1;

        if(ret == 0) { /* EoF, UUID was not found */
            uuidstr[0] = 0;
            break;
        }

        sscanf(line, "%s %s\n", iden, uuidbuf);
        if(STREQ(iden, "#UUID:")) {
            strncpy(uuidstr, uuidbuf, VIR_UUID_STRING_BUFLEN);
            break;
        }
    }
    close(fd);

    return 0;
}

/* Do actual checking for UUID presence in conf file,
 * assign if not present.
 */
int
openvzSetDefinedUUID(int vpsid, unsigned char *uuid)
{
    char conf_file[PATH_MAX];
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (uuid == NULL)
        return -1;

   if (openvzLocateConfFile(vpsid, conf_file, PATH_MAX)<0)
       return -1;

    if (openvzGetVPSUUID(vpsid, uuidstr))
        return -1;

    if (uuidstr[0] == 0) {
        FILE *fp = fopen(conf_file, "a"); /* append */
        if (fp == NULL)
          return -1;

        virUUIDFormat(uuid, uuidstr);

        /* Record failure if fprintf or fclose fails,
           and be careful always to close the stream.  */
        if ((fprintf(fp, "\n#UUID: %s\n", uuidstr) < 0)
            + (fclose(fp) == EOF))
            return -1;
    }

    return 0;
}

static int
openvzSetUUID(int vpsid){
    unsigned char uuid[VIR_UUID_BUFLEN];

    virUUIDGenerate(uuid);

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
    int vpsid, res;
    char ext[8];

    conf_dir = openvzLocateConfDir();
    if (conf_dir == NULL)
        return -1;

    dp = opendir(conf_dir);
    if(dp == NULL) {
        VIR_FREE(conf_dir);
        return 0;
    }

    while((dent = readdir(dp))) {
        res = sscanf(dent->d_name, "%d.%5s", &vpsid, ext);
        if(!(res == 2 && STREQ(ext, "conf")))
            continue;
        if(vpsid > 0) /* '0.conf' belongs to the host, ignore it */
            openvzSetUUID(vpsid);
    }
    closedir(dp);
    VIR_FREE(conf_dir);
    return 0;
}

