/*
 * openvz_conf.c: config functions for managing OpenVZ VEs
 *
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 * Author: Shuveb Hussain <shuveb@binarykarma.com>
 */

#ifdef WITH_OPENVZ

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <strings.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include <libvirt/virterror.h>

#include "openvz_conf.h"
#include "openvz_driver.h"
#include "uuid.h"
#include "buf.h"


/* For errors internal to this library. */
static void
error (virConnectPtr conn, virErrorNumber code, const char *info)
{
    const char *errmsg;

    errmsg = __virErrorMsg (code, info);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
                     code, VIR_ERR_ERROR, errmsg, info, NULL, 0, 0,
                     errmsg, info);
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
        if (!memcmp(vm->vmdef->uuid, uuid, OPENVZ_UUID_MAX))
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
        if (!strcmp(vm->vmdef->name, name))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

/* Free all memory associated with a struct openvz_vm object */
void 
openvzFreeVMDef(struct openvz_vm_def *def) {
    struct ovz_quota *quota = def->fs.quota;
    struct ovz_ip *ip = def->net.ips;
    struct ovz_ns *ns = def->net.ns;

    while (quota) {
        struct ovz_quota *prev = quota;
        quota = quota->next;
        free(prev);
    }
    while (ip) {
        struct ovz_ip *prev = ip;
        ip = ip->next;
        free(prev);
    }
    while (ns) {
        struct ovz_ns *prev = ns;
        ns = ns->next;
        free(prev);
    }

    free(def);
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

    if (!(def = calloc(1, sizeof(struct openvz_vm_def)))) {
        error(conn, VIR_ERR_NO_MEMORY, "xmlXPathContext");
        return NULL;
    }

    /* Prepare parser / xpath context */
    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "incorrect root element");
        goto bail_out;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        error(conn, VIR_ERR_NO_MEMORY, "xmlXPathContext");
        goto bail_out;
    }


    /* Find out what type of QEMU virtualization to use */
    if (!(prop = xmlGetProp(root, BAD_CAST "type"))) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "missing domain type attribute");
        goto bail_out;
    }

    if (strcmp((char *)prop, "openvz")){
        error(conn, VIR_ERR_INTERNAL_ERROR, "invalid domain type attribute");
        goto bail_out;
    }
    free(prop);
    prop = NULL;

    /* Extract domain name */
    obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        error(conn, VIR_ERR_INTERNAL_ERROR,"invalid domain name");
        goto bail_out;
    }
    if (0/* check if VPS ID is < 101 */) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "VPS ID is less than 101");
        goto bail_out;
    }
    strcpy(def->name, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);

    /* Extract domain uuid */
    obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        int err;
        if ((err = virUUIDGenerate(def->uuid))) {
            error(conn, VIR_ERR_INTERNAL_ERROR,
                             "Failed to generate UUID");
            goto bail_out;
        }
    } else if (virUUIDParse((const char *)obj->stringval, def->uuid) < 0) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "malformed uuid element");
        goto bail_out;
    }
    xmlXPathFreeObject(obj);

    /* Extract filesystem info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/filesystem/template[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        error(conn, VIR_ERR_OS_TYPE, NULL);
        goto bail_out;
    }
    strcpy(def->fs.tmpl, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);

    /* TODO Add quota processing here */

    /* TODO analysis of the network devices */

    xmlXPathFreeContext(ctxt);

    return def;

 bail_out:
    if (prop)
        free(prop);
    if (obj)
        xmlXPathFreeObject(obj);
    if (ctxt)
        xmlXPathFreeContext(ctxt);
    openvzFreeVMDef(def);
    return NULL;
}

struct openvz_vm_def *
openvzParseVMDef(virConnectPtr conn,
                const char *xmlStr,
                const char *displayName) {
    xmlDocPtr xml;
    struct openvz_vm_def *def = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        error(conn, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = openvzParseXML(conn, xml);

    xmlFreeDoc(xml);

    return def;
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
        error(conn, VIR_ERR_INTERNAL_ERROR, "popen failed");
        return NULL;
    }
    pnext = &vm; 
    while(!feof(fp)) { 
        *pnext = malloc(sizeof(struct openvz_vm));
        if(!*pnext) {
            error(conn, VIR_ERR_INTERNAL_ERROR, "malloc failed");
            return NULL;
        }
        
        if(!vm)
            vm = *pnext;

        fscanf(fp, "%d %s\n", &veid, status);
        if(strcmp(status, "stopped")) { 
            (*pnext)->status = VIR_DOMAIN_RUNNING;
            driver->num_active ++;
            (*pnext)->vpsid = veid;
        }
        else {
            (*pnext)->status = VIR_DOMAIN_SHUTOFF;
            driver->num_inactive ++;
            (*pnext)->vpsid = -1;    /* inactive domains don't have their ID set in libvirt,
                                        thought this doesn't make sense for OpenVZ */
        }

        vmdef = malloc(sizeof(struct openvz_vm_def));
        if(!vmdef) {
            error(conn, VIR_ERR_INTERNAL_ERROR, "malloc failed");
            return NULL;
        }
        
        snprintf(vmdef->name, OPENVZ_NAME_MAX,  "%i", veid);
        openvzGetVPSUUID(veid, uuidstr);
        ret = virUUIDParse(uuidstr, vmdef->uuid);

        if(ret == -1) {
            error(conn, VIR_ERR_INTERNAL_ERROR, "UUID in config file malformed");
            return NULL;
        }

        (*pnext)->vmdef = vmdef;
        pnext = &(*pnext)->next;
    }
    return vm;
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
openvzGetVPSUUID(int vpsid, char *uuidbuf)
{
    char conf_file[PATH_MAX];
    char line[1024];
    char uuid[1024];
    char iden[1024];
    char *conf_dir;
    int fd, ret;

    conf_dir = openvzLocateConfDir();
    sprintf(conf_file, "%s/%d.conf", conf_dir, vpsid);
    free(conf_dir);

    fd = open(conf_file, O_RDWR);
    if(fd == -1)
        return -1;

    while(1) {
        ret = openvz_readline(fd, line, sizeof(line));
        if(ret == -1)
            return -1;

        if(ret == 0) { /* EoF, UUID was not found */
            uuidbuf[0] = (char)NULL;
            break;
        }

        sscanf(line, "%s %s\n", iden, uuid);
        if(!strcmp(iden, "#UUID:")) {
            strncpy(uuidbuf, uuid, VIR_UUID_STRING_BUFLEN);
            break;
        }
    }
    return 0;
}

/* Do actual checking for UUID presence in conf file,
 * assign if not present.
 */

static int 
openvzSetUUID(int vpsid)
{
    char conf_file[PATH_MAX];
    char uuid[VIR_UUID_STRING_BUFLEN];
    unsigned char new_uuid[VIR_UUID_BUFLEN];
    char *conf_dir;
    int fd, ret, i;

    conf_dir = openvzLocateConfDir();
    sprintf(conf_file, "%s/%d.conf", conf_dir, vpsid);
    free(conf_dir);

    fd = open(conf_file, O_RDWR);
    if(fd == -1)
        return -1;

    ret = openvzGetVPSUUID(vpsid, uuid);
    if(ret == -1)
        return -1;

    if(uuid[0] == (int)NULL) {
        virUUIDGenerate(new_uuid);
        bzero(uuid, VIR_UUID_STRING_BUFLEN);
        for(i = 0; i < VIR_UUID_BUFLEN; i ++)
            sprintf(uuid + (i * 2), "%02x", (unsigned char)new_uuid[i]);
    
        lseek(fd, 0, SEEK_END);
        write(fd, "\n#UUID: ", 8);
        write(fd, uuid, strlen(uuid));
        write(fd, "\n", 1);
        close(fd);
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

    dp = opendir(conf_dir);
    if(dp == NULL) {
        free(conf_dir);
        return 0;
    }

    while((dent = readdir(dp))) {
        res = sscanf(dent->d_name, "%d.%5s", &vpsid, ext);
        if(!(res == 2 && !strcmp(ext, "conf")))
            continue;
        if(vpsid > 0) /* '0.conf' belongs to the host, ignore it */
            openvzSetUUID(vpsid);
    }
    closedir(dp);
    free(conf_dir);
    return 0;
}

#endif

