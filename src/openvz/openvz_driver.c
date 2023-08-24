/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2010-2016 Red Hat, Inc.
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

#include <sys/types.h>
#include <poll.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include "virerror.h"
#include "datatypes.h"
#include "openvz_driver.h"
#include "openvz_util.h"
#include "virbuffer.h"
#include "openvz_conf.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virlog.h"
#include "vircommand.h"
#include "viruri.h"
#include "virnetdevtap.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

VIR_LOG_INIT("openvz.openvz_driver");

#define OPENVZ_NB_MEM_PARAM 3

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openvzConnectGetMaxVcpus(virConnectPtr conn, const char *type);
static int openvzDomainGetMaxVcpus(virDomainPtr dom);
static int openvzDomainSetVcpusInternal(virDomainObj *vm,
                                        unsigned int nvcpus,
                                        virDomainXMLOption *xmlopt);
static int openvzDomainSetMemoryInternal(virDomainObj *vm,
                                         unsigned long long memory);
static int openvzGetVEStatus(virDomainObj *vm, int *status, int *reason);

struct openvz_driver ovz_driver;


static virDomainObj *
openvzDomObjFromDomainLocked(struct openvz_driver *driver,
                             const unsigned char *uuid)
{
    virDomainObj *vm;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(vm = virDomainObjListFindByUUID(driver->domains, uuid))) {
        virUUIDFormat(uuid, uuidstr);

        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s'"), uuidstr);
        return NULL;
    }

    return vm;
}


static virDomainObj *
openvzDomObjFromDomain(struct openvz_driver *driver,
                       const unsigned char *uuid)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return openvzDomObjFromDomainLocked(driver, uuid);
}


/* generate arguments to create OpenVZ container
   return -1 - error
           0 - OK
   Caller has to free the cmd
*/
static virCommand *
openvzDomainDefineCmd(virDomainDef *vmdef)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL,
                                                     "--quiet",
                                                     "create",
                                                     NULL);

    if (vmdef == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container is not defined"));
        return NULL;
    }

    virCommandAddArgList(cmd, vmdef->name, "--name", vmdef->name, NULL);

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
        virCommandAddArgList(cmd, "--ostemplate", vmdef->fss[0]->src, NULL);
    }

    return g_steal_pointer(&cmd);
}


static int openvzSetInitialConfig(virDomainDef *vmdef)
{
    int vpsid;

    if (vmdef->nfss > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only one filesystem supported"));
        return -1;
    }

    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_TEMPLATE &&
        vmdef->fss[0]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filesystem is not of type 'template' or 'mount'"));
        return -1;
    }


    if (vmdef->nfss == 1 &&
        vmdef->fss[0]->type == VIR_DOMAIN_FS_TYPE_MOUNT)
    {

        if (virStrToLong_i(vmdef->name, NULL, 10, &vpsid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not convert domain name to VEID"));
            return -1;
        }

        if (openvzCopyDefaultConfig(vpsid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not copy default config"));
            return -1;
        }

        if (openvzWriteVPSConfigParam(vpsid, "VE_PRIVATE", vmdef->fss[0]->src->path) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set the source dir for the filesystem"));
            return -1;
        }
    } else {
        g_autoptr(virCommand) cmd = openvzDomainDefineCmd(vmdef);
        if (virCommandRun(cmd, NULL) < 0)
            return -1;
    }

    return 0;
}


static int
openvzSetDiskQuota(virDomainDef *vmdef,
                   virDomainFSDef *fss,
                   bool persist)
{
    unsigned long long sl, hl;
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL,
                                                     "--quiet",
                                                     "set",
                                                     vmdef->name,
                                                     NULL);
    if (persist)
        virCommandAddArg(cmd, "--save");

    if (fss->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
        if (fss->space_hard_limit) {
            hl = VIR_DIV_UP(fss->space_hard_limit, 1024);
            virCommandAddArg(cmd, "--diskspace");

            if (fss->space_soft_limit) {
                sl = VIR_DIV_UP(fss->space_soft_limit, 1024);
                virCommandAddArgFormat(cmd, "%lld:%lld", sl, hl);
            } else {
                virCommandAddArgFormat(cmd, "%lld", hl);
            }
        } else if (fss->space_soft_limit) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Can't set soft limit without hard limit"));
            return -1;
        }

        if (virCommandRun(cmd, NULL) < 0)
            return -1;
    }

    return 0;
}


static char *
openvzDomainGetHostname(virDomainPtr dom, unsigned int flags)
{
    char *hostname = NULL;
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;

    virCheckFlags(0, NULL);
    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    hostname = openvzVEGetStringParam(dom, "hostname");
    if (hostname == NULL)
        goto cleanup;

    /* vzlist prints an unset hostname as '-' */
    if (STREQ(hostname, "-")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Hostname of '%1$s' is unset"), vm->def->name);
        VIR_FREE(hostname);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return hostname;
}


static virDomainPtr openvzDomainLookupByID(virConnectPtr conn,
                                           int id)
{
    struct openvz_driver *driver = conn->privateData;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vm = virDomainObjListFindByID(driver->domains, id);
    }

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id '%1$d'"), id);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int openvzConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct  openvz_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    *version = driver->version;
    return 0;
}


static char *openvzConnectGetHostname(virConnectPtr conn G_GNUC_UNUSED)
{
    return virGetHostname();
}


static char *openvzDomainGetOSType(virDomainPtr dom)
{
    struct  openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

    virDomainObjEndAPI(&vm);
    return ret;
}


static virDomainPtr openvzDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid)
{
    struct  openvz_driver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    if (!(vm = openvzDomObjFromDomain(driver, uuid)))
        return NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr openvzDomainLookupByName(virConnectPtr conn,
                                             const char *name)
{
    struct openvz_driver *driver = conn->privateData;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vm = virDomainObjListFindByName(driver->domains, name);
    }

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int openvzDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int state;
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &state, NULL) == -1)
        goto cleanup;
    info->state = state;

    if (info->state != VIR_DOMAIN_RUNNING) {
        info->cpuTime = 0;
    } else {
        if (openvzGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot read cputime for domain %1$d"), dom->id);
            goto cleanup;
        }
    }

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
openvzDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = openvzGetVEStatus(vm, state, reason);

    virDomainObjEndAPI(&vm);
    return ret;
}


static int openvzDomainIsActive(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = virDomainObjIsActive(obj);

    virDomainObjEndAPI(&obj);
    return ret;
}


static int openvzDomainIsPersistent(virDomainPtr dom)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = obj->persistent;

    virDomainObjEndAPI(&obj);
    return ret;
}

static int openvzDomainIsUpdated(virDomainPtr dom G_GNUC_UNUSED)
{
    return 0;
}

static char *openvzDomainGetXMLDesc(virDomainPtr dom, unsigned int flags) {
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = virDomainDefFormat(vm->def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

    virDomainObjEndAPI(&vm);
    return ret;
}


static int openvzDomainSuspend(virDomainPtr dom)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "chkpnt", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virCommandAddArgList(cmd, vm->def->name, "--suspend", NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int openvzDomainResume(virDomainPtr dom)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "chkpnt", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virCommandAddArgList(cmd, vm->def->name, "--resume", NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "stop", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    dom->id = -1;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainShutdown(virDomainPtr dom)
{
    return openvzDomainShutdownFlags(dom, 0);
}

static int
openvzDomainDestroy(virDomainPtr dom)
{
    return openvzDomainShutdownFlags(dom, 0);
}

static int
openvzDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    return openvzDomainShutdownFlags(dom, flags);
}

static int openvzDomainReboot(virDomainPtr dom,
                              unsigned int flags)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "restart", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    virCommandAddArg(cmd, vm->def->name);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
openvzGenerateVethName(int veid, char *dev_name_ve)
{
    int     ifNo = 0;
    char    *ret;

    if (sscanf(dev_name_ve, "%*[^0-9]%d", &ifNo) != 1)
        return NULL;
    ret = g_strdup_printf("veth%d.%d.", veid, ifNo);
    return ret;
}

static char *
openvzGenerateContainerVethName(int veid)
{
    char *temp = NULL;
    char *name = NULL;

    /* try to get line "^NETIF=..." from config */
    if (openvzReadVPSConfigParam(veid, "NETIF", &temp) <= 0) {
        name = g_strdup("eth0");
    } else {
        char *saveptr = NULL;
        char *s;
        int max = 0;

        /* get maximum interface number (actually, it is the last one) */
        for (s = strtok_r(temp, ";", &saveptr); s; s = strtok_r(NULL, ";", &saveptr)) {
            int x;

            if (sscanf(s, "ifname=eth%d", &x) != 1) return NULL;
            if (x > max) max = x;
        }

        /* set new name */
        name = g_strdup_printf("eth%d", max + 1);
    }

    VIR_FREE(temp);

    return name;
}

static int
openvzDomainSetNetwork(virConnectPtr conn, const char *vpsid,
                       virDomainNetDef *net,
                       virBuffer *configBuf)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virMacAddr host_mac;
    char host_macaddr[VIR_MAC_STRING_BUFLEN];
    struct openvz_driver *driver =  conn->privateData;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *guest_ifname = NULL;

    if (net == NULL)
        return 0;

    if (vpsid == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container ID is not specified"));
        return -1;
    }

    if (net->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET)
        return 0;

    cmd = virCommandNewArgList(VZCTL, "--quiet", "set", vpsid, NULL);

    virMacAddrFormat(&net->mac, macaddr);
    virDomainNetGenerateMAC(driver->xmlopt, &host_mac);
    virMacAddrFormat(&host_mac, host_macaddr);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
         net->guestIP.nips == 0)) {
        g_auto(virBuffer)buf = VIR_BUFFER_INITIALIZER;
        int veid = openvzGetVEID(vpsid);

        /* if net is ethernet and the user has specified guest interface name,
         * let's use it; otherwise generate a new one */
        if (net->ifname_guest) {
            guest_ifname = g_strdup(net->ifname_guest);
        } else {
            guest_ifname = openvzGenerateContainerVethName(veid);
            if (guest_ifname == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not generate eth name for container"));
                return -1;
            }
        }

        /* if user doesn't specified host interface name,
         * than we need to generate it */
        if (net->ifname == NULL) {
            net->ifname = openvzGenerateVethName(veid, guest_ifname);
            if (net->ifname == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not generate veth name"));
                return -1;
            }
        }

        virBufferAdd(&buf, guest_ifname, -1); /* Guest dev */
        virBufferAsprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferAsprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferAsprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
                virBufferAsprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
            } else {
                virBufferAsprintf(configBuf, "ifname=%s", guest_ifname);
                virBufferAsprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
                virBufferAsprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
                virBufferAsprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
                virBufferAsprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
            }
        }

        /* --netif_add ifname[,mac,host_ifname,host_mac] */
        virCommandAddArg(cmd, "--netif_add");
        virCommandAddArgBuffer(cmd, &buf);
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
               net->guestIP.nips > 0) {
        size_t i;

        /* --ipadd ip */
        for (i = 0; i < net->guestIP.nips; i++) {
            g_autofree char *ipStr = virSocketAddrFormat(&net->guestIP.ips[i]->address);
            if (!ipStr)
                return -1;
            virCommandAddArgList(cmd, "--ipadd", ipStr, NULL);
        }
    }

    /* TODO: processing NAT and physical device */

    virCommandAddArg(cmd, "--save");
    return virCommandRun(cmd, NULL);
}


static int
openvzDomainSetNetworkConfig(virConnectPtr conn,
                             virDomainDef *def)
{
    size_t i;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char *param;
    int first = 1;
    struct openvz_driver *driver =  conn->privateData;

    for (i = 0; i < def->nnets; i++) {
        if (driver->version < VZCTL_BRIDGE_MIN_VERSION &&
            def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (first)
                first = 0;
            else
                virBufferAddLit(&buf, ";");
        }

        if (openvzDomainSetNetwork(conn, def->name, def->nets[i], &buf) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not configure network"));
            return -1;
        }
    }

    if (driver->version < VZCTL_BRIDGE_MIN_VERSION && def->nnets) {
        param = virBufferContentAndReset(&buf);
        if (param) {
            if (openvzWriteVPSConfigParam(strtoI(def->name), "NETIF", param) < 0) {
                VIR_FREE(param);
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot replace NETIF config"));
                return -1;
            }
            VIR_FREE(param);
        }
    }

    return 0;
}


static virDomainPtr
openvzDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct openvz_driver *driver =  conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", vmdef->name, "\n") < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, &vmdef,
                                   driver->xmlopt,
                                   0, NULL)))
        goto cleanup;
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (vm->def->nfss == 1) {
        if (openvzSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (virDomainDefHasVcpusOffline(vm->def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpu count must equal maximum"));
        goto cleanup;
    }
    if (virDomainDefGetVcpusMax(vm->def)) {
        if (openvzDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def),
                                         driver->xmlopt) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
            goto cleanup;
        }
    }

    if (vm->def->mem.cur_balloon > 0) {
        if (openvzDomainSetMemoryInternal(vm, vm->def->mem.cur_balloon) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set memory size"));
            goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, -1);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
openvzDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return openvzDomainDefineXMLFlags(conn, xml, 0);
}

static virDomainPtr
openvzDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "start", NULL);
    struct openvz_driver *driver =  conn->privateData;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   &vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    /* All OpenVZ domains seem to be persistent - this is a bit of a violation
     * of this libvirt API which is intended for transient domain creation */
    vm->persistent = 1;

    if (openvzSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (vm->def->nfss == 1) {
        if (openvzSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (openvzDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    if (virDomainDefGetVcpusMax(vm->def) > 0) {
        if (openvzDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def),
                                         driver->xmlopt) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
            goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
openvzDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "start", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        vm = virDomainObjListFindByName(driver->domains, dom->name);
    }

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), dom->name);
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("domain is not in shutoff state"));
        goto cleanup;
    }

    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    dom->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainCreate(virDomainPtr dom)
{
    return openvzDomainCreateWithFlags(dom, 0);
}

static int
openvzDomainUndefineFlags(virDomainPtr dom,
                          unsigned int flags)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "start", "destroy", NULL);
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    int status;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(0, -1);

    if (!(vm = openvzDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainUndefine(virDomainPtr dom)
{
    return openvzDomainUndefineFlags(dom, 0);
}
static int
openvzDomainSetAutostart(virDomainPtr dom, int autostart)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", NULL);
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    virCommandAddArgList(cmd, "set", vm->def->name,
                         "--onboot", autostart ? "yes" : "no",
                         "--save", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *value = NULL;
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzReadVPSConfigParam(strtoI(vm->def->name), "ONBOOT", &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not read container config"));
        goto cleanup;
    }

    *autostart = 0;
    if (STREQ(value, "yes"))
        *autostart = 1;
    ret = 0;

 cleanup:
    VIR_FREE(value);

    virDomainObjEndAPI(&vm);
    return ret;
}

static int openvzConnectGetMaxVcpus(virConnectPtr conn G_GNUC_UNUSED,
                                    const char *type)
{
    if (type == NULL || STRCASEEQ(type, "openvz"))
        return 1028; /* OpenVZ has no limitation */

    virReportError(VIR_ERR_INVALID_ARG,
                   _("unknown type '%1$s'"), type);
    return -1;
}

static int
openvzDomainGetVcpusFlags(virDomainPtr dom G_GNUC_UNUSED,
                          unsigned int flags)
{
    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported flags (0x%1$x)"), flags);
        return -1;
    }

    return openvzConnectGetMaxVcpus(NULL, "openvz");
}

static int openvzDomainGetMaxVcpus(virDomainPtr dom)
{
    return openvzDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}

static int openvzDomainSetVcpusInternal(virDomainObj *vm,
                                        unsigned int nvcpus,
                                        virDomainXMLOption *xmlopt)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", NULL);
    char        str_vcpus[32];
    unsigned int pcpus;
    pcpus = virHostCPUGetCount();
    if (pcpus > 0 && pcpus < nvcpus)
        nvcpus = pcpus;

    g_snprintf(str_vcpus, sizeof(str_vcpus), "%d", nvcpus);

    virCommandAddArgList(cmd, "set", vm->def->name,
                         "--cpus", str_vcpus, "--save", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (virDomainDefSetVcpusMax(vm->def, nvcpus, xmlopt) < 0)
        return -1;

    if (virDomainDefSetVcpus(vm->def, nvcpus) < 0)
        return -1;

    return 0;
}

static int openvzDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                                     unsigned int flags)
{
    virDomainObj *        vm;
    struct openvz_driver   *driver = dom->conn->privateData;
    int                     ret = -1;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported flags (0x%1$x)"), flags);
        return -1;
    }

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (nvcpus == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Number of vCPUs should be >= 1"));
        goto cleanup;
    }

    if (openvzDomainSetVcpusInternal(vm, nvcpus, driver->xmlopt) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set number of vCPUs"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return openvzDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}


static int
openvzConnectURIProbe(char **uri)
{
    if (!virFileExists("/proc/vz"))
        return 0;

    if (access("/proc/vz", W_OK) < 0)
        return 0;

    *uri = g_strdup("openvz:///system");
    return 1;
}


static virDrvOpenStatus openvzConnectOpen(virConnectPtr conn,
                                          virConnectAuthPtr auth G_GNUC_UNUSED,
                                          virConf *conf G_GNUC_UNUSED,
                                          unsigned int flags)
{
    struct openvz_driver *driver;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* If path isn't /system, then they typoed, so tell them correct path */
    if (STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected OpenVZ URI path '%1$s', try openvz:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!virFileExists("/proc/vz")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("OpenVZ control file /proc/vz does not exist"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (access("/proc/vz", W_OK) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("OpenVZ control file /proc/vz is not accessible"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    driver = g_new0(struct openvz_driver, 1);

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(driver->caps = openvzCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = openvzXMLOption(driver)))
        goto cleanup;

    if (openvzLoadDomains(driver) < 0)
        goto cleanup;

    if (openvzExtractVersion(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    openvzFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int openvzConnectClose(virConnectPtr conn)
{
    struct openvz_driver *driver = conn->privateData;

    openvzFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *openvzConnectGetType(virConnectPtr conn G_GNUC_UNUSED) {
    return "OpenVZ";
}

static int openvzConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Encryption is not relevant / applicable to way we talk to openvz */
    return 0;
}

static int openvzConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* We run CLI tools directly so this is secure */
    return 1;
}

static int
openvzConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static char *openvzConnectGetCapabilities(virConnectPtr conn) {
    struct openvz_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return virCapabilitiesFormatXML(driver->caps);
}

static int openvzConnectListDomains(virConnectPtr conn G_GNUC_UNUSED,
                                    int *ids, int nids)
{
    int got = 0;
    VIR_AUTOCLOSE outfd = -1;
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZLIST, "-ovpsid", "-H", NULL);

    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        return -1;

    while (got < nids) {
        char *endptr;
        char buf[32];
        int veid;

        if (openvz_readline(outfd, buf, 32) == 0)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %1$s"), buf);
            continue;
        }
        ids[got++] = veid;
    }

    if (virCommandWait(cmd, NULL) < 0)
        return -1;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        return -1;
    }

    return got;
}

static int openvzConnectNumOfDomains(virConnectPtr conn)
{
    struct openvz_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
}

static int openvzConnectListDefinedDomains(virConnectPtr conn G_GNUC_UNUSED,
                                           char **const names, int nnames) {
    int got = 0;
    VIR_AUTOCLOSE outfd = -1;
    int ret = -1;
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZLIST,
                                                     "-ovpsid", "-H", "-S", NULL);

    /* the -S options lists only stopped domains */
    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto cleanup;

    while (got < nnames) {
        char vpsname[32];
        char buf[32];
        char *endptr;
        int veid;

        if (openvz_readline(outfd, buf, 32) == 0)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %1$s"), buf);
            continue;
        }
        g_snprintf(vpsname, sizeof(vpsname), "%d", veid);
        names[got++] = g_strdup(vpsname);
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        goto cleanup;
    }

    ret = got;
 cleanup:
    if (ret < 0) {
        for (; got >= 0; got--)
            VIR_FREE(names[got]);
    }
    return ret;
}

static int openvzGetProcessInfo(unsigned long long *cpuTime, int vpsid)
{
    FILE *fp;
    char *line = NULL;
    size_t line_size = 0;
    unsigned long long usertime, systime, nicetime;
    int readvps = vpsid + 1;  /* ensure readvps is initially different */
    ssize_t ret;
    int err = 0;

/* read statistic from /proc/vz/vestat.
 sample:
Version: 2.2
   VEID     user      nice     system     uptime                 idle   other..
     33       78         0       1330   59454597      142650441835148   other..
     55      178         0       5340   59424597      542650441835148   other..
*/

    if ((fp = fopen("/proc/vz/vestat", "r")) == NULL)
        return -1;

    /* search line with VEID=vpsid */
    while (1) {
        ret = getline(&line, &line_size, fp);
        if (ret < 0) {
            err = !feof(fp);
            break;
        }

        if (sscanf(line, "%d %llu %llu %llu",
                   &readvps, &usertime, &nicetime, &systime) == 4
            && readvps == vpsid) { /* found vpsid */
            /* convert jiffies to nanoseconds */
            *cpuTime = (1000ull * 1000ull * 1000ull
                        * (usertime + nicetime  + systime)
                        / (unsigned long long)sysconf(_SC_CLK_TCK));
            break;
        }
    }

    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
    if (err)
        return -1;

    if (readvps != vpsid) /*not found*/
        return -1;

    return 0;
}

static int openvzConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct openvz_driver *driver =  conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
}

static int
openvzDomainSetMemoryInternal(virDomainObj *vm,
                              unsigned long long mem)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", NULL);
    char str_mem[16];

    /* memory has to be changed its format from kbyte to byte */
    g_snprintf(str_mem, sizeof(str_mem), "%llu", mem * 1024);

    virCommandAddArgList(cmd, "set", vm->def->name,
                         "--kmemsize", str_mem, "--save", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}


static int
openvzDomainGetBarrierLimit(virDomainPtr domain,
                            const char *param,
                            unsigned long long *barrier,
                            unsigned long long *limit)
{
    char *endp;
    g_autofree char *output = NULL;
    const char *tmp;
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZLIST, "--no-header", NULL);

    virCommandSetOutputBuffer(cmd, &output);
    virCommandAddArgFormat(cmd, "-o%s.b,%s.l", param, param);
    virCommandAddArg(cmd, domain->name);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    tmp = output;
    virSkipSpaces(&tmp);
    if (virStrToLong_ull(tmp, &endp, 10, barrier) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Can't parse limit from vzlist output '%1$s'"), output);
        return -1;
    }
    tmp = endp;
    virSkipSpaces(&tmp);
    if (virStrToLong_ull(tmp, &endp, 10, limit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Can't parse barrier from vzlist output '%1$s'"), output);
        return -1;
    }

    return 0;
}


static int
openvzDomainSetBarrierLimit(virDomainPtr domain,
                            const  char *param,
                            unsigned long long barrier,
                            unsigned long long limit)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VZCTL, "--quiet", "set", NULL);

    /* LONG_MAX indicates unlimited so reject larger values */
    if (barrier > LONG_MAX || limit > LONG_MAX) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to set %1$s for %2$s: value too large"), param,
                       domain->name);
        return -1;
    }

    virCommandAddArg(cmd, domain->name);
    virCommandAddArgFormat(cmd, "--%s", param);
    virCommandAddArgFormat(cmd, "%llu:%llu", barrier, limit);
    virCommandAddArg(cmd, "--save");

    return virCommandRun(cmd, NULL);
}


static int
openvzDomainGetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int *nparams,
                                unsigned int flags)
{
    size_t i;
    const char *name;
    long kb_per_pages;
    unsigned long long barrier, limit, val;

    virCheckFlags(0, -1);

    kb_per_pages = openvzKBPerPages();
    if (kb_per_pages < 0)
        return -1;

    if (*nparams == 0) {
        *nparams = OPENVZ_NB_MEM_PARAM;
        return 0;
    }

    for (i = 0; i <= *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0:
            name = "privvmpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                return -1;

            val = (limit == LONG_MAX) ? VIR_DOMAIN_MEMORY_PARAM_UNLIMITED : limit * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                return -1;
            break;

        case 1:
            name = "privvmpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                return -1;

            val = (barrier == LONG_MAX) ? VIR_DOMAIN_MEMORY_PARAM_UNLIMITED : barrier * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                return -1;
            break;

        case 2:
            name = "vmguarpages";
            if (openvzDomainGetBarrierLimit(domain, name, &barrier, &limit) < 0)
                return -1;

            val = (barrier == LONG_MAX) ? 0ull : barrier * kb_per_pages;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                return -1;
            break;
        }
    }

    if (*nparams > OPENVZ_NB_MEM_PARAM)
        *nparams = OPENVZ_NB_MEM_PARAM;

    return 0;
}


static int
openvzDomainSetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    size_t i;
    long kb_per_pages;

    kb_per_pages = openvzKBPerPages();
    if (kb_per_pages < 0)
        return -1;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_MEMORY_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];
        unsigned long long barrier, limit;

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            if (openvzDomainGetBarrierLimit(domain, "privvmpages",
                                            &barrier, &limit) < 0)
                return -1;
            limit = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "privvmpages",
                                            barrier, limit) < 0)
                return -1;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            if (openvzDomainGetBarrierLimit(domain, "privvmpages",
                                            &barrier, &limit) < 0)
                return -1;
            barrier = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "privvmpages",
                                            barrier, limit) < 0)
                return -1;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE)) {
            barrier = params[i].value.ul / kb_per_pages;
            if (openvzDomainSetBarrierLimit(domain, "vmguarpages",
                                            barrier, LONG_MAX) < 0)
                return -1;
        }
    }

    return 0;
}


static int
openvzGetVEStatus(virDomainObj *vm, int *status, int *reason)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *outbuf = NULL;
    char *line;
    int state;

    cmd = virCommandNewArgList(VZLIST, vm->def->name, "-ostatus", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if ((line = strchr(outbuf, '\n')) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to parse vzlist output"));
        return -1;
    }
    *line++ = '\0';

    state = virDomainObjGetState(vm, reason);

    if (STREQ(outbuf, "running")) {
        /* There is no way to detect whether a domain is paused or not
         * with vzlist */
        if (state == VIR_DOMAIN_PAUSED)
            *status = state;
        else
            *status = VIR_DOMAIN_RUNNING;
    } else {
        *status = VIR_DOMAIN_SHUTOFF;
    }

    return 0;
}

static int
openvzDomainInterfaceStats(virDomainPtr dom,
                           const char *device,
                           virDomainInterfaceStatsPtr stats)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virDomainNetDef *net = NULL;
    int ret = -1;

    if (!(vm = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (!(net = virDomainNetFind(vm->def, device)))
        goto cleanup;

    if (virNetDevTapInterfaceStats(net->ifname, stats,
                                   !virDomainNetTypeSharesHostView(net)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
openvzUpdateDevice(virDomainDef *vmdef,
                   virDomainDeviceDef *dev,
                   bool persist)
{
    virDomainFSDef *fs;
    virDomainFSDef *cur;
    int pos;

    if (dev->type == VIR_DOMAIN_DEVICE_FS) {
        fs = dev->data.fs;
        pos = virDomainFSIndexByName(vmdef, fs->dst);

        if (pos < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %1$s doesn't exist."), fs->dst);
            return -1;
        }
        cur = vmdef->fss[pos];

        /* We only allow updating the quota */
        if (STRNEQ(cur->src->path, fs->src->path)
            || cur->type != fs->type
            || cur->accessmode != fs->accessmode
            || cur->wrpolicy != fs->wrpolicy
            || cur->readonly != fs->readonly) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can only modify disk quota"));
            return -1;
        }

        if (openvzSetDiskQuota(vmdef, fs, persist) < 0)
            return -1;
        cur->space_hard_limit = fs->space_hard_limit;
        cur->space_soft_limit = fs->space_soft_limit;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Can't modify device type '%1$s'"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return 0;
}


static int
openvzDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                              unsigned int flags)
{
    int ret = -1;
    int veid;
    struct  openvz_driver *driver = dom->conn->privateData;
    virDomainDeviceDef *dev = NULL;
    virDomainObj *vm = NULL;
    virDomainDef *def = NULL;
    bool persist = false;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = openvzDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (virStrToLong_i(vm->def->name, NULL, 10, &veid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not convert domain name to VEID"));
        goto cleanup;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    dev = virDomainDeviceDefParse(xml, def, driver->xmlopt, NULL,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (!dev)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        persist = true;

    if (openvzUpdateDevice(def, dev, persist) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct openvz_driver *driver = conn->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);
    return virDomainObjListExport(driver->domains, conn, domains, NULL, flags);
}



static int
openvzNodeGetInfo(virConnectPtr conn G_GNUC_UNUSED,
                  virNodeInfoPtr nodeinfo)
{
    return virCapabilitiesGetNodeInfo(nodeinfo);
}


static int
openvzNodeGetCPUStats(virConnectPtr conn G_GNUC_UNUSED,
                      int cpuNum,
                      virNodeCPUStatsPtr params,
                      int *nparams,
                      unsigned int flags)
{
    return virHostCPUGetStats(cpuNum, params, nparams, flags);
}


static int
openvzNodeGetMemoryStats(virConnectPtr conn G_GNUC_UNUSED,
                         int cellNum,
                         virNodeMemoryStatsPtr params,
                         int *nparams,
                         unsigned int flags)
{
    return virHostMemGetStats(cellNum, params, nparams, flags);
}


static int
openvzNodeGetCellsFreeMemory(virConnectPtr conn G_GNUC_UNUSED,
                             unsigned long long *freeMems,
                             int startCell,
                             int maxCells)
{
    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}


static unsigned long long
openvzNodeGetFreeMemory(virConnectPtr conn G_GNUC_UNUSED)
{
    unsigned long long freeMem;
    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;
    return freeMem;
}


static int
openvzNodeGetCPUMap(virConnectPtr conn G_GNUC_UNUSED,
                    unsigned char **cpumap,
                    unsigned int *online,
                    unsigned int flags)
{
    return virHostCPUGetMap(cpumap, online, flags);
}


static int
openvzConnectSupportsFeature(virConnectPtr conn G_GNUC_UNUSED, int feature)
{
    int supported;

    if (virDriverFeatureIsGlobal(feature, &supported))
        return supported;

    switch ((virDrvFeature) feature) {
    case VIR_DRV_FEATURE_REMOTE:
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    case VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER:
    case VIR_DRV_FEATURE_FD_PASSING:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Global feature %1$d should have already been handled"),
                       feature);
        return -1;
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_V3:
        return 1;
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATION_V1:
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    default:
        return 0;
    }
}


static char *
openvzDomainMigrateBegin3Params(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                char **cookieout G_GNUC_UNUSED,
                                int *cookieoutlen G_GNUC_UNUSED,
                                unsigned int flags)
{
    virDomainObj *vm = NULL;
    struct openvz_driver *driver = domain->conn->privateData;
    char *xml = NULL;
    int status;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        return NULL;

    if (!(vm = openvzDomObjFromDomain(driver, domain->uuid)))
        return NULL;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    xml = virDomainDefFormat(vm->def, driver->xmlopt,
                             VIR_DOMAIN_DEF_FORMAT_SECURE);

 cleanup:
    virDomainObjEndAPI(&vm);
    return xml;
}

static int
openvzDomainMigratePrepare3Params(virConnectPtr dconn,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein G_GNUC_UNUSED,
                                  int cookieinlen G_GNUC_UNUSED,
                                  char **cookieout G_GNUC_UNUSED,
                                  int *cookieoutlen G_GNUC_UNUSED,
                                  char **uri_out,
                                  unsigned int fflags G_GNUC_UNUSED)
{
    struct openvz_driver *driver = dconn->privateData;
    const char *dom_xml = NULL;
    const char *uri_in = NULL;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    g_autofree char *my_hostname = NULL;
    const char *hostname = NULL;
    g_autoptr(virURI) uri = NULL;
    int ret = -1;

    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto error;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_in) < 0)
        goto error;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        goto error;
    }

    if (!(def = virDomainDefParseString(dom_xml, driver->xmlopt,
                                        NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto error;

    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto error;

    if (!uri_in) {
        if ((my_hostname = virGetHostname()) == NULL)
            goto error;

        if (STRPREFIX(my_hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost, but migration requires an FQDN"));
            goto error;
        }

        hostname = my_hostname;
    } else {
        uri = virURIParse(uri_in);

        if (uri == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unable to parse URI: %1$s"),
                           uri_in);
            goto error;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing host in migration URI: %1$s"),
                           uri_in);
            goto error;
        }

        hostname = uri->server;
    }

    *uri_out = g_strdup_printf("ssh://%s", hostname);

    ret = 0;
    goto done;

 error:
    if (vm)
        virDomainObjListRemove(driver->domains, vm);

 done:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainMigratePerform3Params(virDomainPtr domain,
                                  const char *dconnuri G_GNUC_UNUSED,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein G_GNUC_UNUSED,
                                  int cookieinlen G_GNUC_UNUSED,
                                  char **cookieout G_GNUC_UNUSED,
                                  int *cookieoutlen G_GNUC_UNUSED,
                                  unsigned int flags)
{
    struct openvz_driver *driver = domain->conn->privateData;
    virDomainObj *vm = NULL;
    const char *uri_str = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int ret = -1;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_str) < 0)
        goto cleanup;

    if (!(vm = openvzDomObjFromDomain(driver, domain->uuid)))
        goto cleanup;

    /* parse dst host:port from uri */
    uri = virURIParse(uri_str);
    if (uri == NULL || uri->server == NULL)
        goto cleanup;

    cmd = virCommandNew(VZMIGRATE);
    if (flags & VIR_MIGRATE_LIVE)
        virCommandAddArg(cmd, "--live");
    virCommandAddArg(cmd, uri->server);
    virCommandAddArg(cmd, vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainPtr
openvzDomainMigrateFinish3Params(virConnectPtr dconn,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein G_GNUC_UNUSED,
                                 int cookieinlen G_GNUC_UNUSED,
                                 char **cookieout G_GNUC_UNUSED,
                                 int *cookieoutlen G_GNUC_UNUSED,
                                 unsigned int flags,
                                 int cancelled)
{
    struct openvz_driver *driver = dconn->privateData;
    virDomainObj *vm = NULL;
    const char *dname = NULL;
    virDomainPtr dom = NULL;
    int status;

    if (cancelled)
        goto cleanup;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        goto cleanup;

    if (!dname ||
        !(vm = virDomainObjListFindByName(driver->domains, dname))) {
        /* Migration obviously failed if the domain doesn't exist */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Migration failed. No domain on destination host with matching name '%1$s'"),
                       NULLSTR(dname));
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not running on destination host"));
        goto cleanup;
    }

    vm->def->id = strtoI(vm->def->name);
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_MIGRATED);

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
openvzDomainMigrateConfirm3Params(virDomainPtr domain,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein G_GNUC_UNUSED,
                                  int cookieinlen G_GNUC_UNUSED,
                                  unsigned int flags,
                                  int cancelled)
{
    struct openvz_driver *driver = domain->conn->privateData;
    virDomainObj *vm = NULL;
    int status;
    int ret = -1;

    virCheckFlags(OPENVZ_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, OPENVZ_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (!(vm = openvzDomObjFromDomain(driver, domain->uuid)))
        goto cleanup;

    if (cancelled) {
        if (openvzGetVEStatus(vm, &status, NULL) == -1)
            goto cleanup;

        if (status == VIR_DOMAIN_RUNNING) {
            ret = 0;
        } else {
            VIR_DEBUG("Domain '%s' does not recover after failed migration",
                      vm->def->name);
        }

        goto cleanup;
    }

    vm->def->id = -1;

    VIR_DEBUG("Domain '%s' successfully migrated", vm->def->name);

    virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObj *obj;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = openvzDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = 0;

    virDomainObjEndAPI(&obj);
    return ret;
}



static virHypervisorDriver openvzHypervisorDriver = {
    .name = "OPENVZ",
    .connectURIProbe = openvzConnectURIProbe,
    .connectOpen = openvzConnectOpen, /* 0.3.1 */
    .connectClose = openvzConnectClose, /* 0.3.1 */
    .connectGetType = openvzConnectGetType, /* 0.3.1 */
    .connectGetVersion = openvzConnectGetVersion, /* 0.5.0 */
    .connectGetHostname = openvzConnectGetHostname, /* 0.9.12 */
    .connectGetMaxVcpus = openvzConnectGetMaxVcpus, /* 0.4.6 */
    .nodeGetInfo = openvzNodeGetInfo, /* 0.3.2 */
    .nodeGetCPUStats = openvzNodeGetCPUStats, /* 0.9.12 */
    .nodeGetMemoryStats = openvzNodeGetMemoryStats, /* 0.9.12 */
    .nodeGetCellsFreeMemory = openvzNodeGetCellsFreeMemory, /* 0.9.12 */
    .nodeGetFreeMemory = openvzNodeGetFreeMemory, /* 0.9.12 */
    .nodeGetCPUMap = openvzNodeGetCPUMap, /* 1.0.0 */
    .connectGetCapabilities = openvzConnectGetCapabilities, /* 0.4.6 */
    .connectListDomains = openvzConnectListDomains, /* 0.3.1 */
    .connectNumOfDomains = openvzConnectNumOfDomains, /* 0.3.1 */
    .connectListAllDomains = openvzConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = openvzDomainCreateXML, /* 0.3.3 */
    .domainLookupByID = openvzDomainLookupByID, /* 0.3.1 */
    .domainLookupByUUID = openvzDomainLookupByUUID, /* 0.3.1 */
    .domainLookupByName = openvzDomainLookupByName, /* 0.3.1 */
    .domainSuspend = openvzDomainSuspend, /* 0.8.3 */
    .domainResume = openvzDomainResume, /* 0.8.3 */
    .domainShutdown = openvzDomainShutdown, /* 0.3.1 */
    .domainShutdownFlags = openvzDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = openvzDomainReboot, /* 0.3.1 */
    .domainDestroy = openvzDomainDestroy, /* 0.3.1 */
    .domainDestroyFlags = openvzDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = openvzDomainGetOSType, /* 0.3.1 */
    .domainGetMemoryParameters = openvzDomainGetMemoryParameters, /* 0.9.12 */
    .domainSetMemoryParameters = openvzDomainSetMemoryParameters, /* 0.9.12 */
    .domainGetInfo = openvzDomainGetInfo, /* 0.3.1 */
    .domainGetState = openvzDomainGetState, /* 0.9.2 */
    .domainSetVcpus = openvzDomainSetVcpus, /* 0.4.6 */
    .domainSetVcpusFlags = openvzDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = openvzDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetMaxVcpus = openvzDomainGetMaxVcpus, /* 0.4.6 */
    .domainGetXMLDesc = openvzDomainGetXMLDesc, /* 0.4.6 */
    .connectListDefinedDomains = openvzConnectListDefinedDomains, /* 0.3.1 */
    .connectNumOfDefinedDomains = openvzConnectNumOfDefinedDomains, /* 0.3.1 */
    .domainCreate = openvzDomainCreate, /* 0.3.1 */
    .domainCreateWithFlags = openvzDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = openvzDomainDefineXML, /* 0.3.3 */
    .domainDefineXMLFlags = openvzDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = openvzDomainUndefine, /* 0.3.3 */
    .domainUndefineFlags = openvzDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = openvzDomainGetAutostart, /* 0.4.6 */
    .domainSetAutostart = openvzDomainSetAutostart, /* 0.4.6 */
    .domainInterfaceStats = openvzDomainInterfaceStats, /* 0.9.12 */
    .connectIsEncrypted = openvzConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = openvzConnectIsSecure, /* 0.7.3 */
    .domainIsActive = openvzDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = openvzDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = openvzDomainIsUpdated, /* 0.8.6 */
    .connectIsAlive = openvzConnectIsAlive, /* 0.9.8 */
    .domainUpdateDeviceFlags = openvzDomainUpdateDeviceFlags, /* 0.9.13 */
    .domainGetHostname = openvzDomainGetHostname, /* 0.10.0 */
    .connectSupportsFeature = openvzConnectSupportsFeature, /* 1.2.8 */
    .domainMigrateBegin3Params = openvzDomainMigrateBegin3Params, /* 1.2.8 */
    .domainMigratePrepare3Params = openvzDomainMigratePrepare3Params, /* 1.2.8 */
    .domainMigratePerform3Params = openvzDomainMigratePerform3Params, /* 1.2.8 */
    .domainMigrateFinish3Params = openvzDomainMigrateFinish3Params, /* 1.2.8 */
    .domainMigrateConfirm3Params = openvzDomainMigrateConfirm3Params, /* 1.2.8 */
    .domainHasManagedSaveImage = openvzDomainHasManagedSaveImage, /* 1.2.13 */
};

static virConnectDriver openvzConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "openvz", NULL },
    .hypervisorDriver = &openvzHypervisorDriver,
};

int openvzRegister(void)
{
    return virRegisterConnectDriver(&openvzConnectDriver,
                                    false);
}
