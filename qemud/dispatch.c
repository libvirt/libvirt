/*
 * dispatch.c: (De-)marshall wire messages to driver functions.
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libvirt/virterror.h>

#include "internal.h"
#include "driver.h"
#include "dispatch.h"
#include "conf.h"
extern struct qemud_driver *qemu_driver;


static virConnect conn;

static int qemudDispatchFailure(struct qemud_packet_server_data *out) {
    virErrorPtr err = virGetLastError();
    if (!err)
        err = virConnGetLastError(&conn);

    out->type = QEMUD_SERVER_PKT_FAILURE;

    if (err) {
        out->qemud_packet_server_data_u.failureReply.code = err->code;
        strncpy(out->qemud_packet_server_data_u.failureReply.message,
                err->message, QEMUD_MAX_ERROR_LEN-1);
        out->qemud_packet_server_data_u.failureReply.message[QEMUD_MAX_ERROR_LEN-1] = '\0';
    } else {
        out->qemud_packet_server_data_u.failureReply.code = VIR_ERR_INTERNAL_ERROR;
        strcpy(out->qemud_packet_server_data_u.failureReply.message,
               "Unknown error");
    }
    return 0;
}


static int qemudDispatchGetVersion(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int ret;
    unsigned long version;
    ret = qemudGetVersion(&conn, &version);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_GET_VERSION;
        out->qemud_packet_server_data_u.getVersionReply.versionNum = version;
    }
    return 0;
}

static int qemudDispatchGetNodeInfo(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    virNodeInfo info;
    if (qemudGetNodeInfo(&conn,
                         &info) < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    out->qemud_packet_server_data_u.getNodeInfoReply.memory = info.memory;
    out->qemud_packet_server_data_u.getNodeInfoReply.cpus = info.cpus;
    out->qemud_packet_server_data_u.getNodeInfoReply.mhz = info.mhz;
    out->qemud_packet_server_data_u.getNodeInfoReply.nodes = info.nodes;
    out->qemud_packet_server_data_u.getNodeInfoReply.sockets = info.sockets;
    out->qemud_packet_server_data_u.getNodeInfoReply.cores = info.cores;
    out->qemud_packet_server_data_u.getNodeInfoReply.threads = info.threads;

    out->type = QEMUD_SERVER_PKT_GET_NODEINFO;
    strncpy(out->qemud_packet_server_data_u.getNodeInfoReply.model, info.model,
            sizeof(out->qemud_packet_server_data_u.getNodeInfoReply.model)-1);
    out->qemud_packet_server_data_u.getNodeInfoReply.model[sizeof(out->qemud_packet_server_data_u.getNodeInfoReply.model)-1] = '\0';

    return 0;
}

static int
qemudDispatchGetCapabilities (struct qemud_packet_client_data *in ATTRIBUTE_UNUSED,
                              struct qemud_packet_server_data *out)
{
    char *xml = qemudGetCapabilities(&conn);

    if (strlen(xml) > QEMUD_MAX_XML_LEN) {
        qemudReportError(&conn, NULL, NULL, VIR_ERR_XML_ERROR, NULL);
        qemudDispatchFailure(out);
        free(xml);
        return 0;
    }

    out->type = QEMUD_SERVER_PKT_GET_CAPABILITIES;
    strcpy (out->qemud_packet_server_data_u.getCapabilitiesReply.xml, xml);
    free(xml);
    return 0;
}

static int qemudDispatchListDomains(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int i, ndomains, domains[QEMUD_MAX_NUM_DOMAINS];

    ndomains = qemudListDomains(&conn,
                                domains,
                                QEMUD_MAX_NUM_DOMAINS);
    if (ndomains < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_DOMAINS;
        for (i = 0 ; i < ndomains ; i++) {
            out->qemud_packet_server_data_u.listDomainsReply.domains[i] = domains[i];
        }
        out->qemud_packet_server_data_u.listDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchNumDomains(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int ndomains = qemudNumDomains(&conn);
    if (ndomains < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DOMAINS;
        out->qemud_packet_server_data_u.numDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainCreate(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.domainCreateRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    virDomainPtr dom = qemudDomainCreate(&conn, in->qemud_packet_client_data_u.domainCreateRequest.xml, 0);
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_CREATE;
        out->qemud_packet_server_data_u.domainCreateReply.id = dom->id;
        memcpy(out->qemud_packet_server_data_u.domainCreateReply.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainCreateReply.name, dom->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
        free(dom);
    }
    return 0;
}

static int qemudDispatchDomainLookupByID(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByID(&conn, in->qemud_packet_client_data_u.domainLookupByIDRequest.id);
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_ID;
        memcpy(out->qemud_packet_server_data_u.domainLookupByIDReply.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainLookupByIDReply.name, dom->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainLookupByIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
        free(dom);
    }
    return 0;
}

static int qemudDispatchDomainLookupByUUID(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainLookupByUUIDRequest.uuid);
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_UUID;
        out->qemud_packet_server_data_u.domainLookupByUUIDReply.id = dom->id;
        strncpy(out->qemud_packet_server_data_u.domainLookupByUUIDReply.name, dom->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
        free(dom);
    }
    return 0;
}

static int qemudDispatchDomainLookupByName(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.domainLookupByNameRequest.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    virDomainPtr dom = qemudDomainLookupByName(&conn, in->qemud_packet_client_data_u.domainLookupByNameRequest.name);
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_NAME;
        out->qemud_packet_server_data_u.domainLookupByNameReply.id = dom->id;
        memcpy(out->qemud_packet_server_data_u.domainLookupByNameReply.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);
        free(dom);
    }
    return 0;
}

static int qemudDispatchDomainSuspend(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByID(&conn, in->qemud_packet_client_data_u.domainSuspendRequest.id);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainSuspend(dom);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SUSPEND;
    }
    return 0;
}

static int qemudDispatchDomainResume(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByID(&conn, in->qemud_packet_client_data_u.domainResumeRequest.id);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainResume(dom);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_RESUME;
    }
    return 0;
}

static int qemudDispatchDomainDestroy(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByID(&conn, in->qemud_packet_client_data_u.domainDestroyRequest.id);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainDestroy(dom);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_DESTROY;
    }
    return 0;
}

static int qemudDispatchDomainGetInfo(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainInfo info;
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainGetInfoRequest.uuid);

    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    if (qemudDomainGetInfo(dom, &info) < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_GET_INFO;
        out->qemud_packet_server_data_u.domainGetInfoReply.runstate = info.state;
        out->qemud_packet_server_data_u.domainGetInfoReply.cpuTime = info.cpuTime;
        out->qemud_packet_server_data_u.domainGetInfoReply.maxmem = info.maxMem;
        out->qemud_packet_server_data_u.domainGetInfoReply.memory = info.memory;
        out->qemud_packet_server_data_u.domainGetInfoReply.nrVirtCpu = info.nrVirtCpu;
    }
    return 0;
}

static int qemudDispatchDomainSave(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByID(&conn, in->qemud_packet_client_data_u.domainSaveRequest.id);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.domainSaveRequest.file[PATH_MAX-1] ='\0';

    ret = qemudDomainSave(dom,
                          in->qemud_packet_client_data_u.domainSaveRequest.file);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SAVE;
    }
    return 0;
}

static int qemudDispatchDomainRestore(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret;

    /* Paranoia null termination */
    in->qemud_packet_client_data_u.domainRestoreRequest.file[PATH_MAX-1] ='\0';

    ret = qemudDomainRestore(&conn, in->qemud_packet_client_data_u.domainRestoreRequest.file);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_RESTORE;
        out->qemud_packet_server_data_u.domainRestoreReply.id = ret;
    }
    return 0;
}

static int qemudDispatchDumpXML(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainDumpXMLRequest.uuid);
    char *ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainDumpXML(dom, 0);
    free(dom);
    if (!ret) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DUMP_XML;
        strncpy(out->qemud_packet_server_data_u.domainDumpXMLReply.xml,
                ret, QEMUD_MAX_XML_LEN-1);
        out->qemud_packet_server_data_u.domainDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';
        free(ret);
    }
    return 0;
}

static int qemudDispatchListDefinedDomains(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i, ndomains;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_DOMAINS)))
        return -1;

    ndomains = qemudListDefinedDomains(&conn,
                                       names,
                                       QEMUD_MAX_NUM_DOMAINS);
    for (i = 0 ; i < ndomains ; i++) {
        strncpy(&out->qemud_packet_server_data_u.listDefinedDomainsReply.domains[i*QEMUD_MAX_NAME_LEN],
                names[i],
                QEMUD_MAX_NAME_LEN);
        free(names[i]);
    }

    free(names);
    if (ndomains < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_DEFINED_DOMAINS;
        out->qemud_packet_server_data_u.listDefinedDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchNumDefinedDomains(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int ndomains = qemudNumDefinedDomains(&conn);
    if (ndomains < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DEFINED_DOMAINS;
        out->qemud_packet_server_data_u.numDefinedDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainStart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainStartRequest.uuid);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainStart(dom);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_START;
        out->qemud_packet_server_data_u.domainStartReply.id = dom->id;
    }
    return 0;
}

static int qemudDispatchDomainDefine(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.domainDefineRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    virDomainPtr dom = qemudDomainDefine(&conn, in->qemud_packet_client_data_u.domainDefineRequest.xml);
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_DEFINE;
        memcpy(out->qemud_packet_server_data_u.domainDefineReply.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainDefineReply.name, dom->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainUndefine(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainUndefineRequest.uuid);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }
    ret = qemudDomainUndefine(dom);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_UNDEFINE;
    }
    return 0;
}

static int qemudDispatchNumNetworks(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int nnetworks = qemudNumNetworks(&conn);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_NETWORKS;
        out->qemud_packet_server_data_u.numNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchListNetworks(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_NETWORKS)))
        return -1;

    int nnetworks = qemudListNetworks(&conn,
                                      names,
                                      QEMUD_MAX_NUM_NETWORKS);
    for (i = 0 ; i < nnetworks ; i++) {
        strncpy(&out->qemud_packet_server_data_u.listNetworksReply.networks[i*QEMUD_MAX_NAME_LEN],
                names[i],
                QEMUD_MAX_NAME_LEN);
        free(names[i]);
    }
    free(names);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_NETWORKS;
        out->qemud_packet_server_data_u.listNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchNumDefinedNetworks(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int nnetworks = qemudNumDefinedNetworks(&conn);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DEFINED_NETWORKS;
        out->qemud_packet_server_data_u.numDefinedNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchListDefinedNetworks(struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_NETWORKS)))
        return -1;

    int nnetworks = qemudListDefinedNetworks(&conn,
                                             names,
                                             QEMUD_MAX_NUM_NETWORKS);

    for (i = 0 ; i < nnetworks ; i++) {
        strncpy(&out->qemud_packet_server_data_u.listDefinedNetworksReply.networks[i*QEMUD_MAX_NAME_LEN],
                names[i],
                QEMUD_MAX_NAME_LEN);
        free(names[i]);
    }
    free(names);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_DEFINED_NETWORKS;
        out->qemud_packet_server_data_u.listDefinedNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchNetworkLookupByName(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.networkLookupByNameRequest.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    struct qemud_network *network = qemudFindNetworkByName(qemu_driver, in->qemud_packet_client_data_u.networkLookupByNameRequest.name);
    if (!network) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_NAME;
        memcpy(out->qemud_packet_server_data_u.networkLookupByNameReply.uuid, network->def->uuid, QEMUD_UUID_RAW_LEN);
    }
    return 0;
}

static int qemudDispatchNetworkLookupByUUID(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_network *network = qemudFindNetworkByUUID(qemu_driver, in->qemud_packet_client_data_u.networkLookupByUUIDRequest.uuid);
    if (!network) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_UUID;
        strncpy(out->qemud_packet_server_data_u.networkLookupByUUIDReply.name, network->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchNetworkCreate(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.networkCreateRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    virNetworkPtr net = qemudNetworkCreate(&conn, in->qemud_packet_client_data_u.networkCreateRequest.xml);
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_CREATE;
        memcpy(out->qemud_packet_server_data_u.networkCreateReply.uuid, net->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.networkCreateReply.name, net->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
        free(net);
    }
    return 0;
}

static int qemudDispatchNetworkDefine(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.networkDefineRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    virNetworkPtr net = qemudNetworkDefine(&conn, in->qemud_packet_client_data_u.networkDefineRequest.xml);
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DEFINE;
        memcpy(out->qemud_packet_server_data_u.networkDefineReply.uuid, net->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.networkDefineReply.name, net->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
        free(net);
    }
    return 0;
}

static int qemudDispatchNetworkUndefine(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkUndefineRequest.uuid);
    int ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkUndefine(net);
    free(net);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_UNDEFINE;
    }
    return 0;
}

static int qemudDispatchNetworkStart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkStartRequest.uuid);
    int ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkStart(net);
    free(net);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_START;
    }
    return 0;
}

static int qemudDispatchNetworkDestroy(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkDestroyRequest.uuid);
    int ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkDestroy(net);
    free(net);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DESTROY;
    }
    return 0;
}

static int qemudDispatchNetworkDumpXML(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkDumpXMLRequest.uuid);
    char *ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkDumpXML(net, 0);
    free(net);
    if (!ret) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DUMP_XML;
        strncpy(out->qemud_packet_server_data_u.networkDumpXMLReply.xml, ret, QEMUD_MAX_XML_LEN-1);
        out->qemud_packet_server_data_u.networkDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';
        free(ret);
    }
    return 0;
}

static int qemudDispatchNetworkGetBridgeName(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkDumpXMLRequest.uuid);
    char *ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkGetBridgeName(net);
    free(net);
    if (!ret) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_GET_BRIDGE_NAME;
        strncpy(out->qemud_packet_server_data_u.networkGetBridgeNameReply.ifname, ret, QEMUD_MAX_IFNAME_LEN-1);
        out->qemud_packet_server_data_u.networkGetBridgeNameReply.ifname[QEMUD_MAX_IFNAME_LEN-1] = '\0';
        free(ret);
    }
    return 0;
}

static int qemudDispatchDomainGetAutostart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainGetAutostartRequest.uuid);
    int ret;
    int autostart;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    autostart = 0;

    ret = qemudDomainGetAutostart(dom,
                                  &autostart);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_GET_AUTOSTART;
        out->qemud_packet_server_data_u.networkGetAutostartReply.autostart = (autostart != 0);
    }
    return 0;
}

static int qemudDispatchDomainSetAutostart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virDomainPtr dom = qemudDomainLookupByUUID(&conn, in->qemud_packet_client_data_u.domainSetAutostartRequest.uuid);
    int ret;
    if (!dom) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
        return 0;
    }

    ret = qemudDomainSetAutostart(dom,
                                  in->qemud_packet_client_data_u.domainSetAutostartRequest.autostart);
    free(dom);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SET_AUTOSTART;
    }
    return 0;
}

static int qemudDispatchNetworkGetAutostart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkGetAutostartRequest.uuid);
    int ret;
    int autostart;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    autostart = 0;

    ret = qemudNetworkGetAutostart(net,
                                   &autostart);
    free(net);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_GET_AUTOSTART;
        out->qemud_packet_server_data_u.networkGetAutostartReply.autostart = (autostart != 0);
    }
    return 0;
}

static int qemudDispatchNetworkSetAutostart(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    virNetworkPtr net = qemudNetworkLookupByUUID(&conn, in->qemud_packet_client_data_u.networkGetAutostartRequest.uuid);
    int ret;
    if (!net) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    }

    ret = qemudNetworkSetAutostart(net,
                                   in->qemud_packet_client_data_u.networkSetAutostartRequest.autostart);
    free(net);
    if (ret < 0) {
        if (qemudDispatchFailure(out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_SET_AUTOSTART;
    }
    return 0;
}

typedef int (*clientFunc)(struct qemud_packet_client_data *in, struct qemud_packet_server_data *out);


/* One per message type recorded in qemud_packet_type enum */

clientFunc funcsTransmitRW[QEMUD_CLIENT_PKT_MAX] = {
    qemudDispatchGetVersion,
    qemudDispatchGetNodeInfo,
    qemudDispatchListDomains,
    qemudDispatchNumDomains,
    qemudDispatchDomainCreate,
    qemudDispatchDomainLookupByID,
    qemudDispatchDomainLookupByUUID,
    qemudDispatchDomainLookupByName,
    qemudDispatchDomainSuspend,
    qemudDispatchDomainResume,
    qemudDispatchDomainDestroy,
    qemudDispatchDomainGetInfo,
    qemudDispatchDomainSave,
    qemudDispatchDomainRestore,
    qemudDispatchDumpXML,
    qemudDispatchListDefinedDomains,
    qemudDispatchNumDefinedDomains,
    qemudDispatchDomainStart,
    qemudDispatchDomainDefine,
    qemudDispatchDomainUndefine,
    qemudDispatchNumNetworks,
    qemudDispatchListNetworks,
    qemudDispatchNumDefinedNetworks,
    qemudDispatchListDefinedNetworks,
    qemudDispatchNetworkLookupByUUID,
    qemudDispatchNetworkLookupByName,
    qemudDispatchNetworkCreate,
    qemudDispatchNetworkDefine,
    qemudDispatchNetworkUndefine,
    qemudDispatchNetworkStart,
    qemudDispatchNetworkDestroy,
    qemudDispatchNetworkDumpXML,
    qemudDispatchNetworkGetBridgeName,
    qemudDispatchDomainGetAutostart,
    qemudDispatchDomainSetAutostart,
    qemudDispatchNetworkGetAutostart,
    qemudDispatchNetworkSetAutostart,
    qemudDispatchGetCapabilities,
};

clientFunc funcsTransmitRO[QEMUD_CLIENT_PKT_MAX] = {
    qemudDispatchGetVersion,
    qemudDispatchGetNodeInfo,
    qemudDispatchListDomains,
    qemudDispatchNumDomains,
    NULL,
    qemudDispatchDomainLookupByID,
    qemudDispatchDomainLookupByUUID,
    qemudDispatchDomainLookupByName,
    NULL,
    NULL,
    NULL,
    qemudDispatchDomainGetInfo,
    NULL,
    NULL,
    qemudDispatchDumpXML,
    qemudDispatchListDefinedDomains,
    qemudDispatchNumDefinedDomains,
    NULL,
    NULL,
    NULL,
    qemudDispatchNumNetworks,
    qemudDispatchListNetworks,
    qemudDispatchNumDefinedNetworks,
    qemudDispatchListDefinedNetworks,
    qemudDispatchNetworkLookupByUUID,
    qemudDispatchNetworkLookupByName,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    qemudDispatchNetworkDumpXML,
    qemudDispatchNetworkGetBridgeName,
    qemudDispatchDomainGetAutostart,
    NULL,
    qemudDispatchNetworkGetAutostart,
    NULL,
};

/*
 * Returns -1 if message processing failed - eg, illegal header sizes,
 * a memory error dealing with stuff, or any other bad stuff which
 * should trigger immediate client disconnect
 *
 * Return 0 if message processing succeeded. NB, this does not mean
 * the operation itself succeeded - success/failure of the operation
 * is recorded by the return message type - either it matches the
 * incoming type, or is QEMUD_PKT_FAILURE
 */

int qemudDispatch(struct qemud_server *server ATTRIBUTE_UNUSED,
                  struct qemud_client *client,
                  qemud_packet_client_data *in, qemud_packet_server_data *out) {
    clientFunc *funcs;
    unsigned int type = in->type;
    qemudDebug("> Dispatching request type %d, readonly ? %d",
               in->type, client->readonly);

    if (!conn.magic) {
        qemudOpen(&conn, "qemu:///session", 0);
        conn.magic = 1;
    }
    virResetLastError();
    virConnResetLastError(&conn);

    memset(out, 0, sizeof(*out));

    if (type >= QEMUD_CLIENT_PKT_MAX) {
        qemudDebug("Illegal request type");
        return -1;
    }

    if (client->readonly)
        funcs = funcsTransmitRO;
    else
        funcs = funcsTransmitRW;

    if (!funcs[type]) {
        qemudDebug("Illegal operation requested");
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_DENIED, NULL);
        qemudDispatchFailure(out);
    } else {
        if ((funcs[type])(in, out) < 0) {
            qemudDebug("Dispatch failed");
            return -1;
        }
    }

    qemudDebug("< Returning reply %d", out->type);

    return 0;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
