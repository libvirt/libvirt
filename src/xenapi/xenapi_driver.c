/*
 * xenapi_driver.c: Xen API driver.
 * Copyright (C) 2011-2012 Red Hat, Inc.
 * Copyright (C) 2009, 2010 Citrix Ltd.
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
 * Author: Sharadha Prabhakar <sharadha.prabhakar@citrix.com>
 */

#include <config.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <curl/curl.h>
#include <xen/api/xen_all.h>
#include "internal.h"
#include "domain_conf.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "virauth.h"
#include "util.h"
#include "uuid.h"
#include "memory.h"
#include "buf.h"
#include "viruri.h"
#include "xenapi_driver.h"
#include "xenapi_driver_private.h"
#include "xenapi_utils.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_XENAPI

#define xenapiError(code, ...)                                    \
        virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,       \
                             __FUNCTION__, __LINE__, __VA_ARGS__)


static int xenapiDefaultConsoleType(const char *ostype)
{
    if (STREQ(ostype, "hvm"))
        return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    else
        return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
}


/*
 * getCapsObject
 *
 * Build the capabilities of the hypervisor
 * Return virCapsPtr on success or NULL on failure
 */
static virCapsPtr
getCapsObject (void)
{
    virCapsGuestPtr guest1, guest2;
    virCapsGuestDomainPtr domain1, domain2;
    virCapsPtr caps = virCapabilitiesNew("x86_64", 0, 0);

    if (!caps) {
        virReportOOMError();
        return NULL;
    }
    guest1 = virCapabilitiesAddGuest(caps, "hvm", "x86_64", 0, "", "", 0, NULL);
    if (!guest1)
        goto error_cleanup;
    domain1 = virCapabilitiesAddGuestDomain(guest1, "xen", "", "", 0, NULL);
    if (!domain1)
        goto error_cleanup;
    guest2 = virCapabilitiesAddGuest(caps, "xen", "x86_64", 0, "", "", 0, NULL);
    if (!guest2)
        goto error_cleanup;
    domain2 = virCapabilitiesAddGuestDomain(guest2, "xen", "", "", 0, NULL);
    if (!domain2)
        goto error_cleanup;

    caps->defaultConsoleTargetType = xenapiDefaultConsoleType;

    return caps;

  error_cleanup:
    virCapabilitiesFree(caps);
    return NULL;
}

/*
 * XenapiOpen
 *
 * Authenticates and creates a session with the server
 * Return VIR_DRV_OPEN_SUCCESS on success, else VIR_DRV_OPEN_ERROR
 */
static virDrvOpenStatus
xenapiOpen (virConnectPtr conn, virConnectAuthPtr auth,
            unsigned int flags)
{
    char *username = NULL;
    char *password = NULL;
    struct _xenapiPrivate *privP = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL || conn->uri->scheme == NULL ||
        STRCASENEQ(conn->uri->scheme, "XenAPI")) {
        return VIR_DRV_OPEN_DECLINED;
    }

    if (conn->uri->server == NULL) {
        xenapiSessionErrorHandler(conn, VIR_ERR_INVALID_ARG,
                                  _("Server name not in URI"));
        goto error;
    }

    if (auth == NULL) {
        xenapiSessionErrorHandler(conn, VIR_ERR_AUTH_FAILED,
                                  _("Authentication Credentials not found"));
        goto error;
    }

    if (conn->uri->user != NULL) {
        username = strdup(conn->uri->user);

        if (username == NULL) {
            virReportOOMError();
            goto error;
        }
    } else {
        username = virAuthGetUsername(conn, auth, "xen", NULL, conn->uri->server);

        if (username == NULL) {
            xenapiSessionErrorHandler(conn, VIR_ERR_AUTH_FAILED,
                                      _("Username request failed"));
            goto error;
        }
    }

    password = virAuthGetPassword(conn, auth, "xen", username, conn->uri->server);

    if (password == NULL) {
        xenapiSessionErrorHandler(conn, VIR_ERR_AUTH_FAILED,
                                  _("Password request failed"));
        goto error;
    }

    if (VIR_ALLOC(privP) < 0) {
        virReportOOMError();
        goto error;
    }

    if (virAsprintf(&privP->url, "https://%s", conn->uri->server) < 0) {
        virReportOOMError();
        goto error;
    }

    if (xenapiUtil_ParseQuery(conn, conn->uri, &privP->noVerify) < 0)
        goto error;

    if (!(privP->caps = getCapsObject())) {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Capabilities not found"));
        goto error;
    }

    xmlInitParser();
    xmlKeepBlanksDefault(0);
    xen_init();
    curl_global_init(CURL_GLOBAL_ALL);

    privP->session = xen_session_login_with_password(call_func, privP, username,
                                                     password, xen_api_latest_version);

    if (privP->session == NULL) {
        /* From inspection of xen_session_login_with_password in
         * libxenserver(Version 5.6.100-1), this appears not to be currently
         * possible. The only way for this to be NULL would be on malloc
         * failure, except that the code doesn't check for this and would
         * segfault before returning.
         *
         * We don't assume the reason here for a failure in an external library.
         */
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to allocate xen session"));

        goto error;
    }

    if (privP->session->ok) {
        conn->privateData = privP;

        VIR_FREE(username);
        VIR_FREE(password);

        return VIR_DRV_OPEN_SUCCESS;
    }

    xenapiSessionErrorHandler(conn, VIR_ERR_AUTH_FAILED, NULL);

  error:
    VIR_FREE(username);
    VIR_FREE(password);

    if (privP != NULL) {
        virCapabilitiesFree(privP->caps);

        if (privP->session != NULL)
            xenSessionFree(privP->session);

        VIR_FREE(privP->url);
        VIR_FREE(privP);
    }

    return VIR_DRV_OPEN_ERROR;
}

/*
 * xenapiClose:
 *
 * Returns 0 on successful session logout
 *
 */
static int
xenapiClose (virConnectPtr conn)
{
    struct _xenapiPrivate *priv = conn->privateData;

    virCapabilitiesFree(priv->caps);

    if (priv->session != NULL) {
        xen_session_logout(priv->session);
        priv->session = NULL;
    }

    VIR_FREE(priv->url);
    VIR_FREE(priv);

    conn->privateData = NULL;

    return 0;
}

/*
 *
 * xenapiSupportsFeature
 *
 * Returns 0
 */
static int
xenapiSupportsFeature (virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    default:
        return 0;
    }
}

/*
 * xenapiType:
 *
 *
 * Returns name of the driver
 */
static const char *
xenapiType (virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "XenAPI";
}


/*
 * xenapiGetVersion:
 *
 * Gets the version of XenAPI
 *
 */
static int
xenapiGetVersion (virConnectPtr conn, unsigned long *hvVer)
{
    xen_host host;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    xen_string_string_map *result = NULL;
    int i, ret = -1;
    char *version = NULL;
    if (!(xen_session_get_this_host(session, &host, session))) {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        return -1;
    }
    if (!(xen_host_get_software_version(session, &result, host))) {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        xen_host_free(host);
        return -1;
    }
    xen_host_free(host);
    if (result && result->size > 0) {
        for (i = 0; i < result->size; i++) {
            if (STREQ(result->contents[i].key, "xen")) {
                if (!(version = strdup(result->contents[i].val))) {
                    xen_string_string_map_free(result);
                    virReportOOMError();
                    return -1;
                }
                break;
            }
        }
        if (version) {
            if (virParseVersionString(version, hvVer, false) < 0)
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                          _("Couldn't parse version info"));
            else
                ret = 0;
            xen_string_string_map_free(result);
            VIR_FREE(version);
            return ret;
        }
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Couldn't get version info"));
    }
    return -1;
}


/*
 * xenapiGetHostname:
 *
 *
 * Returns the hostname on success, or NULL on failure
 */
static char *
xenapiGetHostname (virConnectPtr conn)
{
    char *result = NULL;
    xen_host host;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    if (!(xen_session_get_this_host(session, &host, session))) {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        return NULL;
    }
    if (!(xen_host_get_hostname(session, &result, host)))
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    xen_host_free(host);
    return result;
}


/*
 * xenapiGetMaxVcpus:
 *
 *
 * Returns a hardcoded value for Maximum VCPUS
 */
static int
xenapiGetMaxVcpus (virConnectPtr conn ATTRIBUTE_UNUSED, const char *type ATTRIBUTE_UNUSED)
{
    /* this is hardcoded for simplicity and set to a resonable value compared
       to the actual value */
    return 16;
}


/*
 * xenapiNodeGetInfo:
 *
 *
 * Returns Node details on success or else -1
 */
static int
xenapiNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info)
{
    int64_t memory, mhz;
    xen_host_cpu_set *host_cpu_set;
    xen_host_cpu host_cpu;
    xen_host_metrics_set *xen_met_set;
    char *modelname;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    info->nodes = 1;
    info->threads = 1;
    info->sockets = 1;

    if (xen_host_metrics_get_all(session, &xen_met_set)) {
        xen_host_metrics_get_memory_total(session, &memory, xen_met_set->contents[0]);
        info->memory = (unsigned long)(memory / 1024);
        xen_host_metrics_set_free(xen_met_set);
    } else {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Unable to get host metric Information"));
        return -1;
    }
    if (xen_host_cpu_get_all(session, &host_cpu_set)) {
        host_cpu = host_cpu_set->contents[0];
        xen_host_cpu_get_modelname(session, &modelname, host_cpu);
        if (!virStrncpy(info->model, modelname, LIBVIRT_MODELNAME_LEN - 1, LIBVIRT_MODELNAME_LEN)) {
            virReportOOMError();
            xen_host_cpu_set_free(host_cpu_set);
            VIR_FREE(modelname);
            return -1;
        }
        xen_host_cpu_get_speed(session, &mhz, host_cpu);
        info->mhz = (unsigned long)mhz;
        info->cpus = host_cpu_set->size;
        info->cores = host_cpu_set->size;

        xen_host_cpu_set_free(host_cpu_set);
        VIR_FREE(modelname);
        return 0;
    }
    xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Unable to get Host CPU set"));
    return -1;
}

/*
 * xenapiGetCapabilities:
 *
 *
 * Returns capabilities as an XML string
 */
static char *
xenapiGetCapabilities (virConnectPtr conn)
{
    virCapsPtr caps = ((struct _xenapiPrivate *)(conn->privateData))->caps;
    if (caps) {
        char *xml = virCapabilitiesFormatXML(caps);
        if (!xml) goto cleanup;
        return xml;
    }
  cleanup:
    xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Capabilities not available"));
    return NULL;
}


/*
 * xenapiListDomains
 *
 * Collects the list of active domains, and store their ID in @maxids
 * Returns the number of domain found or -1 in case of error
 */
static int
xenapiListDomains (virConnectPtr conn, int *ids, int maxids)
{
    /* vm.list */
    xen_host host;
    xen_vm_set *result = NULL;
    int64_t t0;
    int i;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    if (xen_session_get_this_host(session, &host, session)) {
        xen_host_get_resident_vms(session, &result, host);
        xen_host_free(host);
    } else
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    if (result != NULL) {
        for (i = 0; (i < (result->size)) && (i < maxids); i++) {
            xen_vm_get_domid(session, &t0, result->contents[i]);
            if (t0 > (int64_t)INT_MAX || t0 < (int64_t)INT_MIN) {
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                          _("DomainID can't fit in 32 bits"));
                xen_vm_set_free(result);
                return -1;
            }
            ids[i] = (int)t0;
        }
        xen_vm_set_free(result);
        return i;
    }
    return -1;
}

/*
 * xenapiNumOfDomains
 *
 *
 * Returns the number of domains found or -1 in case of error
 */
static int
xenapiNumOfDomains (virConnectPtr conn)
{
    /* #(vm.list) */
    xen_vm_set *result = NULL;
    xen_host host = NULL;
    int numDomains = -1;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;

    xen_session_get_this_host(session, &host, session);
    if (host != NULL) {
        xen_host_get_resident_vms(session, &result, host);
        if (result != NULL) {
            numDomains = result->size;
            xen_vm_set_free(result);
        }
        xen_host_free(host);
    }
    if (!session->ok)
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return numDomains;
}

/*
 * xenapiDomainCreateXML
 *
 * Launches a new domain based on the XML description
 * Returns the domain pointer or NULL in case of error
 */
static virDomainPtr
xenapiDomainCreateXML (virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    xen_vm_record *record = NULL;
    xen_vm vm = NULL;
    virDomainPtr domP = NULL;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    virCapsPtr caps = ((struct _xenapiPrivate *)(conn->privateData))->caps;
    if (!caps)
        return NULL;

    virCheckFlags(0, NULL);

    virDomainDefPtr defPtr = virDomainDefParseString(caps, xmlDesc,
                                                     1 << VIR_DOMAIN_VIRT_XEN,
                                                     flags);
    createVMRecordFromXml(conn, defPtr, &record, &vm);
    virDomainDefFree(defPtr);
    if (record) {
        unsigned char raw_uuid[VIR_UUID_BUFLEN];
        ignore_value(virUUIDParse(record->uuid, raw_uuid));
        if (vm) {
            if (xen_vm_start(session, vm, false, false)) {
                domP = virGetDomain(conn, record->name_label, raw_uuid);
                if (!domP) {
                    xen_vm_record_free(record);
                    xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                              _("Domain Pointer is invalid"));
                    return domP;
                }
                domP->id = record->domid;
                xen_vm_free(vm);
            }
            else
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        }
        xen_vm_record_free(record);
    }
    else
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return domP;
}

/*
 * xenapiDomainLookupByID
 *
 *
 * Returns a valid domain pointer of the domain with ID same as the one passed
 * or NULL in case of error
 */
static virDomainPtr
xenapiDomainLookupByID (virConnectPtr conn, int id)
{
    int i;
    int64_t domID;
    char *uuid;
    xen_host host;
    xen_vm_set *result;
    xen_vm_record *record;
    unsigned char raw_uuid[VIR_UUID_BUFLEN];
    virDomainPtr domP=NULL;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;

    xen_session_get_this_host(session, &host, session);
    if (host != NULL && session->ok) {
        xen_host_get_resident_vms(session, &result, host);
        if (result != NULL) {
            for (i = 0; i < result->size; i++) {
                xen_vm_get_domid(session, &domID, result->contents[i]);
                if (domID == id) {
                    xen_vm_get_record(session, &record, result->contents[i]);
                    xen_vm_get_uuid(session, &uuid, result->contents[i]);
                    ignore_value(virUUIDParse(uuid, raw_uuid));
                    domP = virGetDomain(conn, record->name_label, raw_uuid);
                    if (domP) {
                        int64_t domid = -1;
                        xen_vm_get_domid(session, &domid, result->contents[i]);
                        domP->id = domid;
                    } else {
                        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                                  _("Domain Pointer not valid"));
                        domP = NULL;
                    }
                    xen_uuid_free(uuid);
                    xen_vm_record_free(record);
                    break;
                }
            }
            xen_vm_set_free(result);
        } else {
            xenapiSessionErrorHandler(conn, VIR_ERR_NO_DOMAIN, NULL);
        }
        xen_host_free(host);
    } else {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    }
    return domP;
}

/*
 * xenapiDomainLookupByUUID
 *
 * Returns the domain pointer of domain with matching UUID
 * or -1 in case of error
 */
static virDomainPtr
xenapiDomainLookupByUUID (virConnectPtr conn,
                          const unsigned char *uuid)
{
    /* vm.get_by_uuid */
    xen_vm vm;
    xen_vm_record *record;
    char uuidStr[VIR_UUID_STRING_BUFLEN];
    virDomainPtr domP = NULL;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    virUUIDFormat(uuid,uuidStr);
    if (xen_vm_get_by_uuid(session, &vm, uuidStr)) {
        xen_vm_get_record(session, &record, vm);
        if (record != NULL) {
            domP = virGetDomain(conn, record->name_label, uuid);
            if (!domP) {
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                          _("Domain Pointer not valid"));
                domP = NULL;
            } else {
                domP->id = record->domid;
            }
            xen_vm_record_free(record);
        }
        else
            xenapiSessionErrorHandler(conn, VIR_ERR_NO_DOMAIN, NULL);
        xen_vm_free(vm);
    } else
        xenapiSessionErrorHandler(conn, VIR_ERR_NO_DOMAIN, NULL);
    return domP;
}

/*
 * xenapiDomainLookupByName
 *
 * Returns the domain pointer of domain with matching name
 * or -1 in case of error
 */
static virDomainPtr
xenapiDomainLookupByName (virConnectPtr conn,
                          const char *name)
{
    /* vm.get_by_name_label */
    xen_vm_set *vms = NULL;
    xen_vm vm;
    char *uuid = NULL;
    unsigned char raw_uuid[VIR_UUID_BUFLEN];
    virDomainPtr domP = NULL;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, (char *)name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return NULL;
        }
        vm = vms->contents[0];
        xen_vm_get_uuid(session, &uuid, vm);
        if (uuid!=NULL) {
            ignore_value(virUUIDParse(uuid, raw_uuid));
            domP = virGetDomain(conn, name, raw_uuid);
            if (domP != NULL) {
                int64_t domid = -1;
                xen_vm_get_domid(session, &domid, vm);
                domP->id = domid;
                xen_uuid_free(uuid);
                xen_vm_set_free(vms);
                return domP;
            } else {
                xen_uuid_free(uuid);
                xen_vm_set_free(vms);
            if (!session->ok)
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                          _("Couldn't get the Domain Pointer"));
                return NULL;
            }
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(conn, VIR_ERR_NO_DOMAIN, NULL);
    return NULL;
}

/*
 * xenapiDomainSuspend
 *
 * a VM is paused
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainSuspend (virDomainPtr dom)
{
    /* vm.pause() */
    xen_vm vm;
    xen_vm_set *vms=NULL;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) &&  vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        } else {
            vm = vms->contents[0];
            if (!xen_vm_pause(session, vm)) {
                xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
                xen_vm_set_free(vms);
                return -1;
            }
            xen_vm_set_free(vms);
            return 0;
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainResume
 *
 * Resumes a VM
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainResume (virDomainPtr dom)
{
    /* vm.unpause() */
    xen_vm vm;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        } else {
            vm = vms->contents[0];
            if (!xen_vm_unpause(session, vm)) {
                xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
                xen_vm_set_free(vms);
                return -1;
            }
            xen_vm_set_free(vms);
            return 0;
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainShutdown
 *
 * shutsdown a VM
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    /* vm.clean_shutdown */
    xen_vm vm;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    virCheckFlags(0, -1);

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        } else {
            vm = vms->contents[0];
            if (!xen_vm_clean_shutdown(session, vm)) {
                xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
                xen_vm_set_free(vms);
                return -1;
            }
            xen_vm_set_free(vms);
            return 0;
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

static int
xenapiDomainShutdown(virDomainPtr dom)
{
    return xenapiDomainShutdownFlags(dom, 0);
}

/*
 * xenapiDomainReboot
 *
 * Reboots a VM
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainReboot (virDomainPtr dom, unsigned int flags)
{
    /* vm.clean_reboot */
    xen_vm vm;
    struct xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    virCheckFlags(0, -1);

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!xen_vm_clean_reboot(session, vm)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        xen_vm_set_free(vms);
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainDestroyFlags:
 * @dom: domain object
 * @flags: an OR'ed set of virDomainDestroyFlagsValues
 *
 * Calling this function with no flags set (equal to zero)
 * is equivalent to calling xenapiDomainDestroy.
 *
 * A VM is hard shutdown
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainDestroyFlags(virDomainPtr dom,
                         unsigned int flags)
{
    /* vm.hard_shutdown */
    xen_vm vm;
    struct xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    virCheckFlags(0, -1);

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!xen_vm_hard_shutdown(session, vm)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        xen_vm_set_free(vms);
        dom->id = -1;
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainDestroy:
 * @dom: domain object
 *
 * See xenapiDomainDestroyFlags
 */
static int
xenapiDomainDestroy(virDomainPtr dom)
{
    return xenapiDomainDestroyFlags(dom, 0);
}
/*
 * xenapiDomainGetOSType
 *
 *
 * Returns OS version on success or NULL in case of error
 */
static char *
xenapiDomainGetOSType (virDomainPtr dom)
{
    xen_vm vm=NULL;
    xen_vm_set *vms;
    char *ostype = NULL;
    char *boot_policy=NULL;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return NULL;
        }
        vm = vms->contents[0];
        if (!xen_vm_get_hvm_boot_policy(session, &boot_policy, vm)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            goto cleanup;
        }
        if (!(ostype = (STREQ(boot_policy,"BIOS order") ? strdup("hvm") : strdup("xen"))))
            virReportOOMError();
        VIR_FREE(boot_policy);
    } else
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);

  cleanup:
    if (vms) xen_vm_set_free(vms);
    return ostype;
}
/*
 * xenapiDomainGetMaxMemory
 *
 * Returns maximum static memory for VM on success
 * or 0 in case of error
 */
static unsigned long long
xenapiDomainGetMaxMemory (virDomainPtr dom)
{
    int64_t mem_static_max = 0;
    xen_vm vm;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return 0;
        }
        vm = vms->contents[0];
        xen_vm_get_memory_static_max(session, &mem_static_max, vm);
        xen_vm_set_free(vms);
        return mem_static_max / 1024;
    } else {
        if (vms) xen_vm_set_free(vms);
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        return 0;
    }
}

/*
 * xenapiDomainSetMaxMemory
 *
 * Sets maximum static memory for VM on success
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainSetMaxMemory (virDomainPtr dom, unsigned long memory)
{
    /* vm.set_memory_static_max */
    xen_vm vm;
    struct xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!(xen_vm_set_memory_static_max(session, vm, memory * 1024))) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        xen_vm_set_free(vms);
    } else {
        if (vms) xen_vm_set_free(vms);
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        return -1;
    }
    return 0;
}

/*
 * xenapiDomainGetInfo:
 *
 * Fills a structure with domain information
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainGetInfo (virDomainPtr dom, virDomainInfoPtr info)
{
    int64_t maxmem = 0, memory = 0, vcpu = 0;
    xen_vm vm;
    xen_vm_record *record;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    info->cpuTime = 0; /* CPU time is not advertised */
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        xen_vm_get_memory_static_max(session, &maxmem, vm);
        info->maxMem = (maxmem / 1024);
        enum xen_vm_power_state state = XEN_VM_POWER_STATE_UNDEFINED;
        xen_vm_get_power_state(session, &state, vm);
        info->state = mapPowerState(state);
        xen_vm_get_record(session, &record, vm);
        if (record != NULL) {
            xen_vm_metrics_get_memory_actual(session, &memory, record->metrics->u.handle);
            info->memory = (memory / 1024);
            xen_vm_record_free(record);
        }
        xen_vm_get_vcpus_max(session, &vcpu, vm);
        info->nrVirtCpu = vcpu;
        xen_vm_set_free(vms);
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainGetState:
 *
 * Retrieves domain status and its reason.
 *
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct _xenapiPrivate *priv = dom->conn->privateData;
    enum xen_vm_power_state powerState = XEN_VM_POWER_STATE_UNDEFINED;
    xen_vm_set *vms = NULL;
    xen_vm vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!xen_vm_get_by_name_label(priv->session, &vms, dom->name) ||
        vms->size == 0) {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (vms->size != 1) {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Domain name is not unique"));
        goto cleanup;
    }

    vm = vms->contents[0];
    xen_vm_get_power_state(priv->session, &powerState, vm);

    *state = mapPowerState(powerState);
    if (reason)
        *reason = 0;

    ret = 0;

cleanup:
    if (vms)
        xen_vm_set_free(vms);
    return ret;
}


/*
 * xenapiDomainSetVcpusFlags
 *
 * Sets the VCPUs on the domain
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainSetVcpusFlags (virDomainPtr dom, unsigned int nvcpus,
                           unsigned int flags)
{
    /* vm.set_vcpus_max */
    xen_vm vm;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    if (flags != VIR_DOMAIN_VCPU_LIVE) {
        xenapiError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"),
                    flags);
        return -1;
    }

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (xen_vm_set_vcpus_number_live(session, vm, (int64_t)nvcpus)) {
            xen_vm_set_free(vms);
            return 0;
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainSetVcpus
 *
 * Sets the VCPUs on the domain
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainSetVcpus (virDomainPtr dom, unsigned int nvcpus)
{
    return xenapiDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_VCPU_LIVE);
}

/*
 * xenapiDomainPinVcpu
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU
 * Returns 0 on success or -1 in case of error
 */
static int
xenapiDomainPinVcpu (virDomainPtr dom, unsigned int vcpu ATTRIBUTE_UNUSED,
                     unsigned char *cpumap, int maplen)
{
    char *value = NULL;
    xen_vm vm;
    xen_vm_set *vms;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if ((value = mapDomainPinVcpu(cpumap, maplen))) {
            xen_vm_remove_from_vcpus_params(session, vm, (char *)"mask");
            if (xen_vm_add_to_vcpus_params(session, vm, (char *)"mask", value)) {
                xen_vm_set_free(vms);
                VIR_FREE(value);
                return 0;
            }
            VIR_FREE(value);
        } else {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return -1;
}

/*
 * xenapiDomainGetVcpus
 *
 * Gets Vcpu information
 * Return number of structures filled on success or -1 in case of error
 */
static int
xenapiDomainGetVcpus (virDomainPtr dom,
                      virVcpuInfoPtr info, int maxinfo,
                      unsigned char *cpumaps, int maplen)
{

    xen_vm_set *vms = NULL;
    xen_vm vm = NULL;
    xen_string_string_map *vcpu_params = NULL;
    int nvcpus = 0, i;
    virDomainInfo domInfo;
    virNodeInfo nodeInfo;
    virVcpuInfoPtr ifptr;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    char *mask = NULL;
    if (cpumaps != NULL && maplen < 1)
        return -1;
    if (xenapiDomainGetInfo(dom, &domInfo) == 0) {
        nvcpus = domInfo.nrVirtCpu;
    } else {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Couldn't fetch Domain Information"));
        return -1;
    }
    if (xenapiNodeGetInfo(dom->conn, &nodeInfo) != 0) {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Couldn't fetch Node Information"));
        return -1;
    }
    if (nvcpus > maxinfo)
        nvcpus = maxinfo;
    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);
    if (!xen_vm_get_by_name_label(session, &vms, dom->name))
        return -1;
    if (vms->size != 1) {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Domain name is not unique"));
        xen_vm_set_free(vms);
        return -1;
    }
    vm = vms->contents[0];
    if (!xen_vm_get_vcpus_params(session, &vcpu_params, vm)) {
        xen_vm_set_free(vms);
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
        return -1;
    }
    for (i = 0; i < vcpu_params->size; i++) {
        if (STREQ(vcpu_params->contents[i].key, "mask")) {
            if (!(mask = strdup(vcpu_params->contents[i].val))){
                 xen_vm_set_free(vms);
                 xen_string_string_map_free(vcpu_params);
                 virReportOOMError();
                 return -1;
            }
            break;
         }
    }
    xen_string_string_map_free(vcpu_params);
    for (i = 0, ifptr = info; i < nvcpus; i++, ifptr++) {
        ifptr->number = i;
        ifptr->state = VIR_VCPU_RUNNING;
        ifptr->cpuTime = 0;
        ifptr->cpu = 0;
        if (mask != NULL)
            getCpuBitMapfromString(mask, VIR_GET_CPUMAP(cpumaps, maplen, i), maplen);
    }
    VIR_FREE(mask);
    xen_vm_set_free(vms);
    return i;
}

/*
 * xenapiDomainGetVcpusFlags
 *
 *
 * Returns Vcpus count on success or -1 in case of error
 */
static int
xenapiDomainGetVcpusFlags (virDomainPtr dom, unsigned int flags)
{
    xen_vm vm;
    xen_vm_set *vms;
    int64_t maxvcpu = 0;
    enum xen_vm_power_state state;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;

    if (flags != (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        xenapiError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"),
                    flags);
        return -1;
    }

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        xen_vm_get_power_state(session, &state, vm);
        if (state == XEN_VM_POWER_STATE_RUNNING) {
            xen_vm_get_vcpus_max(session, &maxvcpu, vm);
        } else {
            maxvcpu = xenapiGetMaxVcpus(dom->conn, NULL);
        }
        xen_vm_set_free(vms);
        return (int)maxvcpu;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return -1;
}

/*
 * xenapiDomainGetMaxVcpus
 *
 *
 * Returns maximum number of Vcpus on success or -1 in case of error
 */
static int
xenapiDomainGetMaxVcpus (virDomainPtr dom)
{
    return xenapiDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}

/*
 * xenapiDomainGetXMLDesc
 *
 *
 * Returns XML string of the domain configuration on success or -1 in case of error
 */
static char *
xenapiDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    xen_vm vm=NULL;
    xen_vm_set *vms;
    xen_string_string_map *result=NULL;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    virDomainDefPtr defPtr = NULL;
    char *boot_policy = NULL;
    unsigned long memory=0;
    int64_t dynamic_mem=0;
    char *val = NULL;
    struct xen_vif_set *vif_set = NULL;
    char *xml;

    /* Flags checked by virDomainDefFormat */

    if (!xen_vm_get_by_name_label(session, &vms, dom->name)) return NULL;
    if (vms->size != 1) {
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Domain name is not unique"));
        xen_vm_set_free(vms);
        return NULL;
    }
    if (VIR_ALLOC(defPtr) < 0) {
        virReportOOMError();
        xen_vm_set_free(vms);
        return NULL;
    }
    vm = vms->contents[0];
    defPtr->virtType = VIR_DOMAIN_VIRT_XEN;
    defPtr->id = dom->id;
    memcpy(defPtr->uuid, dom->uuid, VIR_UUID_BUFLEN);
    if (!(defPtr->name = strdup(dom->name)))
        goto error_cleanup;
    xen_vm_get_hvm_boot_policy(session, &boot_policy, vm);
    if (STREQ(boot_policy,"BIOS order")) {
        if (!(defPtr->os.type = strdup("hvm"))) {
            VIR_FREE(boot_policy);
            goto error_cleanup;
        }
        xen_vm_get_hvm_boot_params(session, &result, vm);
        if (result != NULL) {
            int i;
            for (i = 0; i < result->size; i++) {
                if (STREQ(result->contents[i].key, "order")) {
                    int cnt = 0;
                    while(result->contents[i].val[cnt] != '\0') {
                        defPtr->os.bootDevs[cnt] = map2LibvirtBootOrder(result->contents[i].val[cnt]);
                        cnt++;
                    }
                    defPtr->os.nBootDevs = cnt;
                    break;
                }
            }
            xen_string_string_map_free(result);
        }
        VIR_FREE(boot_policy);
    } else {
        char *value = NULL;
        if (!(defPtr->os.type = strdup("xen"))) {
            VIR_FREE(boot_policy);
            goto error_cleanup;
        }
        if (!(defPtr->os.loader = strdup("pygrub"))) {
            VIR_FREE(boot_policy);
            goto error_cleanup;
        }
        xen_vm_get_pv_kernel(session, &value, vm);
        if (STRNEQ(value, "")) {
            if (!(defPtr->os.kernel = strdup(value))) {
                VIR_FREE(boot_policy);
                VIR_FREE(value);
                goto error_cleanup;
            }
            VIR_FREE(value);
        }
        xen_vm_get_pv_ramdisk(session, &value, vm);
        if (STRNEQ(value, "")) {
            if (!(defPtr->os.initrd = strdup(value))) {
                VIR_FREE(boot_policy);
                VIR_FREE(value);
                goto error_cleanup;
            }
            VIR_FREE(value);
        }
        xen_vm_get_pv_args(session, &value, vm);
        if (STRNEQ(value, "")) {
            if(!(defPtr->os.cmdline = strdup(value))) {
                VIR_FREE(boot_policy);
                VIR_FREE(value);
                goto error_cleanup;
            }
            VIR_FREE(value);
        }
        VIR_FREE(boot_policy);
        if (!(defPtr->os.bootloader = strdup("pygrub")))
            goto error_cleanup;
    }
    xen_vm_get_pv_bootloader_args(session, &val, vm);
    if (STRNEQ(val, "")) {
        if (!(defPtr->os.bootloaderArgs = strdup(val))) {
            VIR_FREE(val);
            goto error_cleanup;
        }
        VIR_FREE(val);
    }
    memory = xenapiDomainGetMaxMemory(dom);
    defPtr->mem.max_balloon = memory;
    if (xen_vm_get_memory_dynamic_max(session, &dynamic_mem, vm)) {
        defPtr->mem.cur_balloon = (unsigned long) (dynamic_mem / 1024);
    } else {
        defPtr->mem.cur_balloon = memory;
    }
    defPtr->maxvcpus = defPtr->vcpus = xenapiDomainGetMaxVcpus(dom);
    enum xen_on_normal_exit action;
    if (xen_vm_get_actions_after_shutdown(session, &action, vm)) {
        defPtr->onPoweroff = xenapiNormalExitEnum2virDomainLifecycle(action);
    }
    if (xen_vm_get_actions_after_reboot(session, &action, vm)) {
        defPtr->onReboot = xenapiNormalExitEnum2virDomainLifecycle(action);
    }
    enum xen_on_crash_behaviour crash;
    if (xen_vm_get_actions_after_crash(session, &crash, vm)) {
        defPtr->onCrash = xenapiCrashExitEnum2virDomainLifecycle(action);
    }
    xen_vm_get_platform(session, &result, vm);
    if (result != NULL) {
        int i;
        for(i = 0; i < result->size; i++) {
            if (STREQ(result->contents[i].val, "true")) {
                if (STREQ(result->contents[i].key, "acpi"))
                    defPtr->features = defPtr->features | (1<<VIR_DOMAIN_FEATURE_ACPI);
                else if (STREQ(result->contents[i].key, "apic"))
                    defPtr->features = defPtr->features | (1<<VIR_DOMAIN_FEATURE_APIC);
                else if (STREQ(result->contents[i].key, "pae"))
                    defPtr->features = defPtr->features | (1<<VIR_DOMAIN_FEATURE_PAE);
                else if (STREQ(result->contents[i].key, "hap"))
                    defPtr->features = defPtr->features | (1<<VIR_DOMAIN_FEATURE_HAP);
                else if (STREQ(result->contents[i].key, "viridian"))
                    defPtr->features = defPtr->features | (1<<VIR_DOMAIN_FEATURE_VIRIDIAN);
            }
        }
        xen_string_string_map_free(result);
    }
    xen_vm_get_vifs(session, &vif_set, vm);
    if (vif_set) {
        int i;
        xen_vif vif;
        xen_vif_record *vif_rec = NULL;
        xen_network network;
        char *bridge = NULL;
        defPtr->nnets = vif_set->size;
        if (VIR_ALLOC_N(defPtr->nets, vif_set->size) < 0) {
            xen_vif_set_free(vif_set);
            goto error_cleanup;
        }
        for (i = 0; i < vif_set->size; i++) {
            if (VIR_ALLOC(defPtr->nets[i]) < 0) {
                xen_vif_set_free(vif_set);
                goto error_cleanup;
            }
            defPtr->nets[i]->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            vif = vif_set->contents[i];
            xen_vif_get_network(session, &network, vif);
            if (network != NULL) {
                xen_network_get_bridge(session, &bridge, network);
                if (bridge != NULL)
                    defPtr->nets[i]->data.bridge.brname = bridge;
                xen_network_free(network);
            }
            xen_vif_get_record(session, &vif_rec, vif);
            if (vif_rec != NULL) {
                if (virMacAddrParse((const char *)vif_rec->mac,defPtr->nets[i]->mac) < 0)
                    xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                              _("Unable to parse given mac address"));
                xen_vif_record_free(vif_rec);
            }
        }
        xen_vif_set_free(vif_set);
    }
    if (vms) xen_vm_set_free(vms);
    xml = virDomainDefFormat(defPtr, flags);
    virDomainDefFree(defPtr);
    return xml;

  error_cleanup:
    virReportOOMError();
    xen_vm_set_free(vms);
    virDomainDefFree(defPtr);
    return NULL;

}

/*
 * xenapiListDefinedDomains
 *
 * list the defined but inactive domains, stores the pointers to the names in @names
 * Returns number of names provided in the array or -1 in case of error
 */
static int
xenapiListDefinedDomains (virConnectPtr conn, char **const names,
                          int maxnames)
{
    int i,j=0,doms;
    xen_vm_set *result;
    xen_vm_record *record;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    xen_vm_get_all(session, &result);
    if (result != NULL) {
        for (i = 0; i < result->size && j < maxnames; i++) {
            xen_vm_get_record(session, &record, result->contents[i]);
            if (record != NULL) {
                if (record->is_a_template == 0) {
                    char *usenames = NULL;
                    if (!(usenames = strdup(record->name_label))) {
                        virReportOOMError();
                        xen_vm_record_free(record);
                        xen_vm_set_free(result);
                        while (--j >= 0) VIR_FREE(names[j]);
                        return -1;
                    }
                    names[j++] = usenames;
                }
                xen_vm_record_free(record);
            } else {
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                          _("Couldn't get VM record"));
                xen_vm_set_free(result);
                while (--j >= 0) VIR_FREE(names[j]);
                   return -1;
            }
        }
        doms = j;
        xen_vm_set_free(result);
        return doms;
    }
    xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return -1;
}

/*
 * xenapiNumOfDefinedDomains
 *
 * Provides the number of defined but inactive domains
 * Returns number of domains found on success or -1 in case of error
 */
static int
xenapiNumOfDefinedDomains (virConnectPtr conn)
{
    xen_vm_set *result;
    xen_vm_record *record;
    int DomNum = 0, i;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    xen_vm_get_all(session, &result);
    if (result != NULL) {
        for (i = 0; i < result->size; i++) {
            xen_vm_get_record(session, &record, result->contents[i]);
            if (record == NULL && !session->ok) {
                xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
                xen_vm_set_free(result);
                return -1;
            }
            if (record->is_a_template == 0)
                DomNum++;
            xen_vm_record_free(record);
        }
        xen_vm_set_free(result);
        return DomNum;
    }
    xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
    return -1;
}

/*
 * xenapiDomainCreateWithFlags
 *
 * starts a VM
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainCreateWithFlags (virDomainPtr dom, unsigned int flags)
{
    xen_vm_set *vms;
    xen_vm vm;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    int64_t domid = -1;

    virCheckFlags(0, -1);

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!xen_vm_start(session, vm, false, false)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }

        xen_vm_get_domid(session, &domid, vm);
        dom->id = domid;

        xen_vm_set_free(vms);
    } else {
        if (vms) xen_vm_set_free(vms);
        xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
        return -1;
    }
    return 0;
}

/*
 * xenapiDomainCreate
 *
 * starts a VM
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainCreate (virDomainPtr dom)
{
    return xenapiDomainCreateWithFlags(dom, 0);
}

/*
 * xenapiDomainDefineXML
 *
 * Defines a domain from the given XML but does not start it
 * Returns 0 on success or -1 in case of error
 */
static virDomainPtr
xenapiDomainDefineXML (virConnectPtr conn, const char *xml)
{
    xen_vm_record *record=NULL;
    xen_vm vm=NULL;
    virDomainPtr domP=NULL;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    virCapsPtr caps = ((struct _xenapiPrivate *)(conn->privateData))->caps;
    if (!caps)
        return NULL;
    virDomainDefPtr defPtr = virDomainDefParseString(caps, xml,
                                                     1 << VIR_DOMAIN_VIRT_XEN, 0);
    if (!defPtr)
        return NULL;

    if (createVMRecordFromXml(conn, defPtr, &record, &vm) != 0) {
        if (!session->ok)
            xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR, NULL);
        else
            xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Couldn't get VM information from XML"));
        virDomainDefFree(defPtr);
        return NULL;
    }
    if (record != NULL) {
        unsigned char raw_uuid[VIR_UUID_BUFLEN];
        ignore_value(virUUIDParse(record->uuid, raw_uuid));
        domP = virGetDomain(conn, record->name_label, raw_uuid);
        if (!domP && !session->ok)
            xenapiSessionErrorHandler(conn, VIR_ERR_NO_DOMAIN, NULL);
        xen_vm_record_free(record);
    }
    else if (vm != NULL)
        xen_vm_free(vm);
    virDomainDefFree(defPtr);
    return domP;
}

/*
 * xenapiDomainUndefineFlags
 *
 * destroys a domain
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainUndefineFlags(virDomainPtr dom, unsigned int flags)
{
    struct xen_vm_set *vms;
    xen_vm vm;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    virCheckFlags(0, -1);

    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!xen_vm_destroy(session, vm)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        xen_vm_set_free(vms);
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

static int
xenapiDomainUndefine(virDomainPtr dom)
{
    return xenapiDomainUndefineFlags(dom, 0);
}

/*
 * xenapiDomainGetAutostart
 *
 * Provides a boolean value indicating whether the domain configured
 * to be automatically started when the host machine boots
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainGetAutostart (virDomainPtr dom, int *autostart)
{
    int i,flag=0;
    xen_vm_set *vms;
    xen_vm vm;
    xen_string_string_map *result;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        if (!xen_vm_get_other_config(session, &result, vm)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        for (i = 0; i < result->size; i++) {
            if (STREQ(result->contents[i].key, "auto_poweron")) {
                flag = 1;
                if (STREQ(result->contents[i].val, "true"))
                    *autostart = 1;
                else
                    *autostart = 0;
                break;
            }
        }
        xen_vm_set_free(vms);
        xen_string_string_map_free(result);
        if (flag == 0) return -1;
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

/*
 * xenapiDomainSetAutostart
 *
 * Configure the domain to be automatically started when the host machine boots
 * Return 0 on success or -1 in case of error
 */
static int
xenapiDomainSetAutostart (virDomainPtr dom, int autostart)
{
    xen_vm_set *vms;
    xen_vm vm;
    char *value;
    xen_session *session = ((struct _xenapiPrivate *)(dom->conn->privateData))->session;
    if (xen_vm_get_by_name_label(session, &vms, dom->name) && vms->size > 0) {
        if (vms->size != 1) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Domain name is not unique"));
            xen_vm_set_free(vms);
            return -1;
        }
        vm = vms->contents[0];
        xen_vm_remove_from_other_config(session, vm, (char *)"auto_poweron");
        if (autostart==1)
            value = (char *)"true";
        else
            value = (char *)"false";
        if (!xen_vm_add_to_other_config(session, vm, (char *)"auto_poweron", value)) {
            xenapiSessionErrorHandler(dom->conn, VIR_ERR_INTERNAL_ERROR, NULL);
            xen_vm_set_free(vms);
            return -1;
        }
        xen_vm_set_free(vms);
        return 0;
    }
    if (vms) xen_vm_set_free(vms);
    xenapiSessionErrorHandler(dom->conn, VIR_ERR_NO_DOMAIN, NULL);
    return -1;
}

static char *
xenapiDomainGetSchedulerType (virDomainPtr dom ATTRIBUTE_UNUSED, int *nparams)
{
    char *result = NULL;

    if (nparams)
        *nparams = 0;
    if (!(result = strdup("credit")))
        virReportOOMError();
    return result;
}

/*
 * xenapiNodeGetFreeMemory
 *
 * provides the free memory available on the Node
 * Returns memory size on success or 0 in case of error
 */
static unsigned long long
xenapiNodeGetFreeMemory (virConnectPtr conn)
{
    xen_host_metrics_set *xen_met_set;
    unsigned long long freeMem = 0;
    xen_session *session = ((struct _xenapiPrivate *)(conn->privateData))->session;
    xen_host_metrics_get_all(session, &xen_met_set);
    if (xen_met_set != NULL) {
        if (!xen_host_metrics_get_memory_free(session, (int64_t *)&freeMem, xen_met_set->contents[0])) {
            xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Couldn't get host metrics - memory information"));
            freeMem = 0;
        }
        xen_host_metrics_set_free(xen_met_set);
    } else {
        xenapiSessionErrorHandler(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Couldn't get host metrics"));
    }
    return freeMem;
}

static int
xenapiDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
}

/*
 * xenapiNodeGetCellsFreeMemory
 *
 *
 * Returns the number of entries filled in freeMems, or -1 in case of error.
 */
static int
xenapiNodeGetCellsFreeMemory (virConnectPtr conn, unsigned long long *freeMems,
                              int startCell, int maxCells)
{
    if (maxCells > 1 && startCell > 0) {
        xenapiSessionErrorHandler(conn, VIR_ERR_NO_SUPPORT, NULL);
        return -1;
    } else {
        freeMems[0] = xenapiNodeGetFreeMemory(conn);
        return 1;
    }
}

static int
xenapiIsAlive(virConnectPtr conn)
{
    struct _xenapiPrivate *priv = conn->privateData;

    if (priv->session && priv->session->ok)
        return 1;
    else
        return 0;
}

/* The interface which we export upwards to libvirt.c. */
static virDriver xenapiDriver = {
    .no = VIR_DRV_XENAPI,
    .name = "XenAPI",
    .open = xenapiOpen, /* 0.8.0 */
    .close = xenapiClose, /* 0.8.0 */
    .supports_feature = xenapiSupportsFeature, /* 0.8.0 */
    .type = xenapiType, /* 0.8.0 */
    .version = xenapiGetVersion, /* 0.8.0 */
    .getHostname = xenapiGetHostname, /* 0.8.0 */
    .getMaxVcpus = xenapiGetMaxVcpus, /* 0.8.0 */
    .nodeGetInfo = xenapiNodeGetInfo, /* 0.8.0 */
    .getCapabilities = xenapiGetCapabilities, /* 0.8.0 */
    .listDomains = xenapiListDomains, /* 0.8.0 */
    .numOfDomains = xenapiNumOfDomains, /* 0.8.0 */
    .domainCreateXML = xenapiDomainCreateXML, /* 0.8.0 */
    .domainLookupByID = xenapiDomainLookupByID, /* 0.8.0 */
    .domainLookupByUUID = xenapiDomainLookupByUUID, /* 0.8.0 */
    .domainLookupByName = xenapiDomainLookupByName, /* 0.8.0 */
    .domainSuspend = xenapiDomainSuspend, /* 0.8.0 */
    .domainResume = xenapiDomainResume, /* 0.8.0 */
    .domainShutdown = xenapiDomainShutdown, /* 0.8.0 */
    .domainShutdownFlags = xenapiDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = xenapiDomainReboot, /* 0.8.0 */
    .domainDestroy = xenapiDomainDestroy, /* 0.8.0 */
    .domainDestroyFlags = xenapiDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = xenapiDomainGetOSType, /* 0.8.0 */
    .domainGetMaxMemory = xenapiDomainGetMaxMemory, /* 0.8.0 */
    .domainSetMaxMemory = xenapiDomainSetMaxMemory, /* 0.8.0 */
    .domainGetInfo = xenapiDomainGetInfo, /* 0.8.0 */
    .domainGetState = xenapiDomainGetState, /* 0.9.2 */
    .domainSetVcpus = xenapiDomainSetVcpus, /* 0.8.0 */
    .domainSetVcpusFlags = xenapiDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = xenapiDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = xenapiDomainPinVcpu, /* 0.8.0 */
    .domainGetVcpus = xenapiDomainGetVcpus, /* 0.8.0 */
    .domainGetMaxVcpus = xenapiDomainGetMaxVcpus, /* 0.8.0 */
    .domainGetXMLDesc = xenapiDomainGetXMLDesc, /* 0.8.0 */
    .listDefinedDomains = xenapiListDefinedDomains, /* 0.8.0 */
    .numOfDefinedDomains = xenapiNumOfDefinedDomains, /* 0.8.0 */
    .domainCreate = xenapiDomainCreate, /* 0.8.0 */
    .domainCreateWithFlags = xenapiDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = xenapiDomainDefineXML, /* 0.8.0 */
    .domainUndefine = xenapiDomainUndefine, /* 0.8.0 */
    .domainUndefineFlags = xenapiDomainUndefineFlags, /* 0.9.5 */
    .domainGetAutostart = xenapiDomainGetAutostart, /* 0.8.0 */
    .domainSetAutostart = xenapiDomainSetAutostart, /* 0.8.0 */
    .domainGetSchedulerType = xenapiDomainGetSchedulerType, /* 0.8.0 */
    .nodeGetCellsFreeMemory = xenapiNodeGetCellsFreeMemory, /* 0.8.0 */
    .nodeGetFreeMemory = xenapiNodeGetFreeMemory, /* 0.8.0 */
    .domainIsUpdated = xenapiDomainIsUpdated, /* 0.8.6 */
    .isAlive = xenapiIsAlive, /* 0.9.8 */
};

/**
 * xenapiRegister:
 *
 *
 * Returns the driver priority or -1 in case of error.
 */
int
xenapiRegister (void)
{
    return virRegisterDriver (&xenapiDriver);
}

/*
 * write_func
 * used by curl to read data from the server
 */
size_t
write_func(void *ptr, size_t size, size_t nmemb, void *comms_)
{
    xen_comms *comms = comms_;
    size_t n = size * nmemb;
#ifdef PRINT_XML
    printf("\n\n---Result from server -----------------------\n");
    printf("%s\n",((char*) ptr));
    fflush(stdout);
#endif
    return (size_t) (comms->func(ptr, n, comms->handle) ? n : 0);
}

/*
 * call_func
 * sets curl options, used with xen_session_login_with_password
 */
int
call_func(const void *data, size_t len, void *user_handle,
          void *result_handle, xen_result_func result_func)
{
    struct _xenapiPrivate *priv = (struct _xenapiPrivate *)user_handle;
#ifdef PRINT_XML
    printf("\n\n---Data to server: -----------------------\n");
    printf("%s\n",((char*) data));
    fflush(stdout);
#endif
    CURL *curl = curl_easy_init();
    if (!curl) {
      return -1;
    }
    xen_comms comms = {
     .func = result_func,
     .handle = result_handle
    };
    curl_easy_setopt(curl, CURLOPT_URL, priv->url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
#ifdef CURLOPT_MUTE
    curl_easy_setopt(curl, CURLOPT_MUTE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &comms);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, priv->noVerify?0:1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, priv->noVerify?0:2);
    CURLcode result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return result;
}
