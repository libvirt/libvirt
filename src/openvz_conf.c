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

#ifdef WITH_OPENVZ

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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include "internal.h"

#include "openvz_driver.h"
#include "openvz_conf.h"
#include "uuid.h"
#include "buf.h"
#include "memory.h"
#include "util.h"

static char *openvzLocateConfDir(void);
static struct openvz_vm_def *openvzParseXML(virConnectPtr conn, xmlDocPtr xml);
static int openvzGetVPSUUID(int vpsid, char *uuidstr);
static int openvzSetUUID(int vpsid);
static int openvzLocateConfFile(int vpsid, char *conffile, int maxlen);

void
openvzError (virConnectPtr conn, virErrorNumber code, const char *fmt, ...)
{
    va_list args;
    char errorMessage[OPENVZ_MAX_ERROR_LEN];
    const char *errmsg;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, OPENVZ_MAX_ERROR_LEN-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    errmsg = __virErrorMsg(code, (errorMessage[0] ? errorMessage : NULL));
    __virRaiseError (conn, NULL, NULL, VIR_FROM_OPENVZ,
                     code, VIR_ERR_ERROR, errmsg, errorMessage, NULL, 0, 0,
                     errmsg, errorMessage);
}

struct openvz_vm
*openvzFindVMByID(const struct openvz_driver *driver, int id) {
    struct openvz_vm *vm = driver->vms;

    while (vm) {
        if (vm->vpsid == id)
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct openvz_vm
*openvzFindVMByUUID(const struct openvz_driver *driver,
                                   const unsigned char *uuid) {
    struct openvz_vm *vm = driver->vms;

    while (vm) {
        if (!memcmp(vm->vmdef->uuid, uuid, VIR_UUID_BUFLEN))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct openvz_vm
*openvzFindVMByName(const struct openvz_driver *driver,
                                   const char *name) {
    struct  openvz_vm *vm = driver->vms;

    while (vm) {
        if (STREQ(vm->vmdef->name, name))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

int
strtoI(const char *str)
{
    int val;

    if (virStrToLong_i(str, NULL, 10, &val) < 0)
        return 0 ;

    return val;
}

void
openvzRemoveInactiveVM(struct openvz_driver *driver, struct openvz_vm *vm)
{
    driver->num_inactive--;
    openvzFreeVM(driver, vm, 1);
}

/* Free all memory associated with a openvz_vm_def structure */
void
openvzFreeVMDef(struct openvz_vm_def *def)
{
    if (def) {
        struct ovz_quota *quota = def->fs.quota;
        struct ovz_ip *ip = def->net.ips;
        struct ovz_ns *ns = def->net.ns;

        while (quota) {
            struct ovz_quota *prev = quota;

            quota = quota->next;
            VIR_FREE(prev);
        }
        while (ip) {
            struct ovz_ip *prev = ip;

            ip = ip->next;
            VIR_FREE(prev);
        }
        while (ns) {
            struct ovz_ns *prev = ns;

            ns = ns->next;
            VIR_FREE(prev);
        }

        VIR_FREE(def);
    }
}

/* Free all memory associated with a openvz_vm structure
 * @checkCallee == 0 then openvzFreeDriver() is callee else some other function
 */
void
openvzFreeVM(struct openvz_driver *driver, struct openvz_vm *vm,
             int checkCallee)
{
    struct openvz_vm *vms;

    if (!vm && !driver)
        return;
    vms = driver->vms;
    if (checkCallee) {
        if (vms == vm)
            driver->vms = vm->next;
        else {
            while (vms) {
                struct openvz_vm *prev = vms;

                vms = vms->next;
                if (vms == vm) {
                    prev->next = vms->next;
                    break;
                }
            }
        }
    }
    if (vms) {
        openvzFreeVMDef(vm->vmdef);
        VIR_FREE(vm);
    }
}

/* Free all memory associated with a openvz_driver structure */
void
openvzFreeDriver(struct openvz_driver *driver)
{
    struct openvz_vm *next;

    if (!driver)
        return;
    if (driver->vms)
        for(next = driver->vms->next; driver->vms; driver->vms = next)
            openvzFreeVM(driver, driver->vms, 0);
    VIR_FREE(driver);
}

struct openvz_vm *
openvzAssignVMDef(virConnectPtr conn,
                  struct openvz_driver *driver, struct openvz_vm_def *def)
{
    struct openvz_vm *vm = NULL;

    if (!driver || !def)
        return NULL;

    if ((vm = openvzFindVMByName(driver, def->name))) {
        if (!openvzIsActiveVM(vm)) {
            openvzFreeVMDef(vm->vmdef);
            vm->vmdef = def;
        }
        else
        {
            openvzLog(OPENVZ_ERR,
                      _("Error already an active OPENVZ VM having id '%s'"),
                      def->name);
            openvzFreeVMDef(def);
            return NULL; /* can't redefine an active domain */
        }

        return vm;
    }

    if (VIR_ALLOC(vm) < 0) {
        openvzFreeVMDef(def);
        openvzError(conn, VIR_ERR_NO_MEMORY, _("vm"));
        return NULL;
    }

    vm->vpsid = -1;     /* -1 needed for to represent inactiveness of domain before 'start' */
    vm->status = VIR_DOMAIN_SHUTOFF;
    vm->vmdef = def;
    vm->next = driver->vms;

    driver->vms = vm;
    driver->num_inactive++;

    return vm;
}

struct openvz_vm_def
*openvzParseVMDef(virConnectPtr conn,
                 const char *xmlStr, const char *displayName)
{
    xmlDocPtr xml;
    struct openvz_vm_def *def = NULL;

    xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "domain.xml", NULL,
            XML_PARSE_NOENT | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!xml) {
        openvzError(conn, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = openvzParseXML(conn, xml);
    xmlFreeDoc(xml);

    return def;
}

/*
 * Parses a libvirt XML definition of a guest, and populates the
 * the openvz_vm struct with matching data about the guests config
 */
static struct openvz_vm_def
*openvzParseXML(virConnectPtr conn,
                        xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlChar *prop = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    struct openvz_vm_def *def;
    struct ovz_ip *ovzIp;
    struct ovz_ns *ovzNs;

    if (VIR_ALLOC(def) < 0) {
        openvzError(conn, VIR_ERR_NO_MEMORY, _("xmlXPathContext"));
        return NULL;
    }

    /* Prepare parser / xpath context */

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("incorrect root element"));
        goto bail_out;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        openvzError(conn, VIR_ERR_NO_MEMORY, _("xmlXPathContext"));
        goto bail_out;
    }

    /* Find out what type of OPENVZ virtualization to use */
    if (!(prop = xmlGetProp(root, BAD_CAST "type"))) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("missing domain type attribute"));
        goto bail_out;
    }

    if (STRNEQ((char *)prop, "openvz")){
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("invalid domain type attribute"));
        goto bail_out;
    }
    VIR_FREE(prop);

    /* Extract domain name */
    obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("invalid domain name"));
        goto bail_out;
    }

    /* rejecting VPS ID <= OPENVZ_RSRV_VM_LIMIT for they are reserved */
    if (strtoI((const char *) obj->stringval) <= OPENVZ_RSRV_VM_LIMIT) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
              _("VPS ID Error (must be an integer greater than 100"));
        goto bail_out;
    }
    strncpy(def->name, (const char *) obj->stringval, OPENVZ_NAME_MAX);
    xmlXPathFreeObject(obj);

    /* Extract domain uuid */
    obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        int err;

        if ((err = virUUIDGenerate(def->uuid))) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("Failed to generate UUID"));
            goto bail_out;
        }
    } else if (virUUIDParse((const char *)obj->stringval, def->uuid) < 0) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("malformed uuid element"));
        goto bail_out;
    }
    xmlXPathFreeObject(obj);

    /* Extract filesystem info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/container/filesystem/template[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||	(obj->stringval == NULL)
            || (obj->stringval[0] == 0)) {
        openvzError(conn, VIR_ERR_OS_TYPE, NULL);
        goto bail_out;
    }
    strncpy(def->fs.tmpl, (const char *) obj->stringval, OPENVZ_TMPL_MAX);
    xmlXPathFreeObject(obj);

    /* TODO Add quota processing here */

    /* TODO analysis of the network devices */


    /*          Extract network                 */
        /*              Extract ipaddress           */
    obj = xmlXPathEval(BAD_CAST"string(/domain/container/network/ipaddress[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) || (obj->stringval == NULL)
            || (obj->stringval[0] == 0)) {
        openvzLog(OPENVZ_WARN,
                  _("No IP address in the given xml config file '%s'"),
                  xml->name);
    }
    if (xmlStrlen(obj->stringval) >= (OPENVZ_IP_MAX)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    _("ipaddress length too long"));
        goto bail_out;
    }
    if (VIR_ALLOC(ovzIp) < 0) {
        openvzLog(OPENVZ_ERR,
                  _("Failed to Create Memory for 'ovz_ip' structure"));
        goto bail_out;
    }
    strncpy(ovzIp->ip, (const char *) obj->stringval, OPENVZ_IP_MAX);
    def->net.ips = ovzIp;
    xmlXPathFreeObject(obj);

        /*              Extract netmask             */
    obj = xmlXPathEval(BAD_CAST "string(/domain/container/network/netmask[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING)
        || (obj->stringval == NULL) || (obj->stringval[0] == 0))
        openvzLog(OPENVZ_WARN,
                  _("No Netmask address in the given xml config file '%s'"),
                  xml->name);

    if (strlen((const char *) obj->stringval) >= (OPENVZ_IP_MAX)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                    _("netmask length too long"));
        goto bail_out;
    }
    strncpy(def->net.ips->netmask, (const char *) obj->stringval, OPENVZ_IP_MAX);
    xmlXPathFreeObject(obj);

        /*              Extract hostname            */
    obj = xmlXPathEval(BAD_CAST "string(/domain/container/network/hostname[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) || (obj->stringval == NULL)
            || (obj->stringval[0] == 0))
        openvzLog(OPENVZ_WARN,
                  _("No hostname in the given xml config file '%s'"),
                  xml->name);

    if (strlen((const char *) obj->stringval) >= (OPENVZ_HOSTNAME_MAX - 1)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("hostname length too long"));
        goto bail_out;
    }
    strncpy(def->net.hostname, (const char *) obj->stringval, OPENVZ_HOSTNAME_MAX - 1);
    xmlXPathFreeObject(obj);

        /*              Extract gateway             */
    obj = xmlXPathEval(BAD_CAST"string(/domain/container/network/gateway[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) || (obj->stringval == NULL)
            || (obj->stringval[0] == 0))
        openvzLog(OPENVZ_WARN,
                  _("No Gateway address in the given xml config file '%s'"),
                  xml->name);

    if (strlen((const char *) obj->stringval) >= (OPENVZ_IP_MAX)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("gateway length too long"));
        goto bail_out;
    }
    strncpy(def->net.def_gw, (const char *) obj->stringval, OPENVZ_IP_MAX);
    xmlXPathFreeObject(obj);

        /*              Extract nameserver          */
    obj = xmlXPathEval(BAD_CAST "string(/domain/container/network/nameserver[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) || (obj->stringval == NULL)
            || (obj->stringval[0] == 0))
        openvzLog(OPENVZ_WARN,
                  _("No Nameserver address inthe given xml config file '%s'"),
                  xml->name);

    if (strlen((const char *) obj->stringval) >= (OPENVZ_IP_MAX)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("nameserver length too long"));
        goto bail_out;
    }
    if (VIR_ALLOC(ovzNs) < 0) {
        openvzLog(OPENVZ_ERR,
                  _("Failed to Create Memory for 'ovz_ns' structure"));
        goto bail_out;
    }
    strncpy(ovzNs->ip, (const char *) obj->stringval, OPENVZ_IP_MAX);
    def->net.ns = ovzNs;
    xmlXPathFreeObject(obj);

    /*          Extract profile         */
    obj = xmlXPathEval(BAD_CAST "string(/domain/container/profile[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) || (obj->stringval == NULL)
            || (obj->stringval[0] == 0)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        goto bail_out;
    }
    if (strlen((const char *) obj->stringval) >= (OPENVZ_PROFILE_MAX - 1)) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("profile length too long"));
        goto bail_out;
    }
    strncpy(def->profile, (const char *) obj->stringval, OPENVZ_PROFILE_MAX - 1);
    xmlXPathFreeObject(obj);

    xmlXPathFreeContext(ctxt);
    return def;

 bail_out:
    VIR_FREE(prop);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    openvzFreeVMDef(def);

    return NULL;
}

struct openvz_vm *
openvzGetVPSInfo(virConnectPtr conn) {
    FILE *fp;
    int veid, ret;
    char status[16];
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    struct openvz_vm *vm;
    struct openvz_vm  **pnext;
    struct openvz_driver *driver;
    struct openvz_vm_def *vmdef;

    vm =  NULL;
    driver = conn->privateData;
    driver->num_active = 0;
    driver->num_inactive = 0;

    if((fp = popen(VZLIST " -a -ovpsid,status -H 2>/dev/null", "r")) == NULL) {
        openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("popen failed"));
        return NULL;
    }
    pnext = &vm;
    while(!feof(fp)) {
        if (VIR_ALLOC(*pnext) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("calloc failed"));
            goto error;
        }

        if(!vm)
            vm = *pnext;

        if (fscanf(fp, "%d %s\n", &veid, status) != 2) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                  _("Failed to parse vzlist output"));
            goto error;
        }
        if(STRNEQ(status, "stopped")) {
            (*pnext)->status = VIR_DOMAIN_RUNNING;
            driver->num_active ++;
            (*pnext)->vpsid = veid;
        }
        else {
            (*pnext)->status = VIR_DOMAIN_SHUTOFF;
            driver->num_inactive ++;
            /*
             * inactive domains don't have their ID set in libvirt,
             * thought this doesn't make sense for OpenVZ
             */
            (*pnext)->vpsid = -1;
        }

        if (VIR_ALLOC(vmdef) < 0) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR, _("calloc failed"));
            goto error;
        }

        snprintf(vmdef->name, OPENVZ_NAME_MAX,  "%i", veid);
        openvzGetVPSUUID(veid, uuidstr);
        ret = virUUIDParse(uuidstr, vmdef->uuid);

        if(ret == -1) {
            openvzError(conn, VIR_ERR_INTERNAL_ERROR,
                  _("UUID in config file malformed"));
            VIR_FREE(vmdef);
            goto error;
        }

        (*pnext)->vmdef = vmdef;
        pnext = &(*pnext)->next;
    }
    return vm;
error:
    while (vm != NULL) {
        struct openvz_vm *next;

        next = vm->next;
        VIR_FREE(vm->vmdef);
        VIR_FREE(vm);
        vm = next;
    }
    return NULL;
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
            if (sf[0] == '=' && (token = strtok_r(sf,"\"\t=\n", &saveptr)) != NULL) {
                strncpy(value, token, maxlen) ;
                value[maxlen-1] = '\0';
                found = 1;
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

static int
openvzSetUUID(int vpsid)
{
    char conf_file[PATH_MAX];
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    unsigned char uuid[VIR_UUID_BUFLEN];

   if (openvzLocateConfFile(vpsid, conf_file, PATH_MAX)<0)
       return -1;

    if (openvzGetVPSUUID(vpsid, uuidstr))
        return -1;

    if (uuidstr[0] == 0) {
        FILE *fp = fopen(conf_file, "a"); /* append */
        if (fp == NULL)
          return -1;

        virUUIDGenerate(uuid);
        virUUIDFormat(uuid, uuidstr);

        /* Record failure if fprintf or fclose fails,
           and be careful always to close the stream.  */
        if ((fprintf(fp, "\n#UUID: %s\n", uuidstr) < 0)
            + (fclose(fp) == EOF))
            return -1;
    }

    return 0;
}

/*
 * Scan VPS config files and see if they have a UUID.
 * If not, assign one. Just append one to the config
 * file as comment so that the OpenVZ tools ignore it.
 *
 */

int openvzAssignUUIDs(void)
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

#endif
