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


static int qemudDispatchFailure(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                struct qemud_packet_server_data *out) {
    out->type = QEMUD_SERVER_PKT_FAILURE;
    out->qemud_packet_server_data_u.failureReply.code = server->errorCode;
    strcpy(out->qemud_packet_server_data_u.failureReply.message, server->errorMessage);
    return 0;
}


static int qemudDispatchGetVersion(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int version = qemudGetVersion(server);
    if (version < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_GET_VERSION;
        out->qemud_packet_server_data_u.getVersionReply.versionNum = version;
    }
    return 0;
}

static int qemudDispatchGetNodeInfo(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    if (qemudGetNodeInfo(&out->qemud_packet_server_data_u.getNodeInfoReply.memory,
                         out->qemud_packet_server_data_u.getNodeInfoReply.model,
                         sizeof(out->qemud_packet_server_data_u.getNodeInfoReply.model),
                         &out->qemud_packet_server_data_u.getNodeInfoReply.cpus,
                         &out->qemud_packet_server_data_u.getNodeInfoReply.mhz,
                         &out->qemud_packet_server_data_u.getNodeInfoReply.nodes,
                         &out->qemud_packet_server_data_u.getNodeInfoReply.sockets,
                         &out->qemud_packet_server_data_u.getNodeInfoReply.cores,
                         &out->qemud_packet_server_data_u.getNodeInfoReply.threads) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
        return 0;
    }

    out->type = QEMUD_SERVER_PKT_GET_NODEINFO;
    out->qemud_packet_server_data_u.getNodeInfoReply.model[sizeof(out->qemud_packet_server_data_u.getNodeInfoReply.model)-1] = '\0';

    return 0;
}

static int
qemudDispatchGetCapabilities (struct qemud_server *server,
                              struct qemud_client *client,
                              struct qemud_packet_client_data *in ATTRIBUTE_UNUSED,
                              struct qemud_packet_server_data *out)
{
    char *xml = qemudGetCapabilities(server);

    if (strlen(xml) > QEMUD_MAX_XML_LEN) {
        qemudReportError (server, VIR_ERR_XML_ERROR, NULL);
        qemudDispatchFailure (server, client, out);
        free(xml);
        return 0;
    }

    out->type = QEMUD_SERVER_PKT_GET_CAPABILITIES;
    strcpy (out->qemud_packet_server_data_u.getCapabilitiesReply.xml, xml);
    free(xml);
    return 0;
}

static int qemudDispatchListDomains(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int i, ndomains, domains[QEMUD_MAX_NUM_DOMAINS];

    ndomains = qemudListDomains(server,
                                domains,
                                QEMUD_MAX_NUM_DOMAINS);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
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

static int qemudDispatchNumDomains(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int ndomains = qemudNumDomains(server);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DOMAINS;
        out->qemud_packet_server_data_u.numDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainCreate(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.domainCreateRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_vm *vm = qemudDomainCreate(server, in->qemud_packet_client_data_u.domainCreateRequest.xml);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_CREATE;
        out->qemud_packet_server_data_u.domainCreateReply.id = vm->id;
        memcpy(out->qemud_packet_server_data_u.domainCreateReply.uuid, vm->def->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainCreateReply.name, vm->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByID(struct qemud_server *server, struct qemud_client *client,
                                         struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_vm *vm = qemudFindVMByID(server, in->qemud_packet_client_data_u.domainLookupByIDRequest.id);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_ID;
        memcpy(out->qemud_packet_server_data_u.domainLookupByIDReply.uuid, vm->def->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainLookupByIDReply.name, vm->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainLookupByIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByUUID(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, in->qemud_packet_client_data_u.domainLookupByUUIDRequest.uuid);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_UUID;
        out->qemud_packet_server_data_u.domainLookupByUUIDReply.id = vm->id;
        strncpy(out->qemud_packet_server_data_u.domainLookupByUUIDReply.name, vm->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByName(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.domainLookupByNameRequest.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    struct qemud_vm *vm = qemudFindVMByName(server, in->qemud_packet_client_data_u.domainLookupByNameRequest.name);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_LOOKUP_BY_NAME;
        out->qemud_packet_server_data_u.domainLookupByNameReply.id = vm->id;
        memcpy(out->qemud_packet_server_data_u.domainLookupByNameReply.uuid, vm->def->uuid, QEMUD_UUID_RAW_LEN);
    }
    return 0;
}

static int qemudDispatchDomainSuspend(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudDomainSuspend(server, in->qemud_packet_client_data_u.domainSuspendRequest.id);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SUSPEND;
    }
    return 0;
}

static int qemudDispatchDomainResume(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudDomainResume(server, in->qemud_packet_client_data_u.domainResumeRequest.id);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_RESUME;
    }
    return 0;
}

static int qemudDispatchDomainDestroy(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    if (qemudDomainDestroy(server, in->qemud_packet_client_data_u.domainDestroyRequest.id) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_DESTROY;
    }
    return 0;
}

static int qemudDispatchDomainGetInfo(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int runstate;
    unsigned long long cpuTime;
    unsigned long memory;
    unsigned long maxmem;
    unsigned int nrVirtCpu;

    int ret = qemudDomainGetInfo(server, in->qemud_packet_client_data_u.domainGetInfoRequest.uuid,
                                 &runstate,
                                 &cpuTime,
                                 &maxmem,
                                 &memory,
                                 &nrVirtCpu);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_GET_INFO;
        out->qemud_packet_server_data_u.domainGetInfoReply.runstate = runstate;
        out->qemud_packet_server_data_u.domainGetInfoReply.cpuTime = cpuTime;
        out->qemud_packet_server_data_u.domainGetInfoReply.maxmem = maxmem;
        out->qemud_packet_server_data_u.domainGetInfoReply.memory = memory;
        out->qemud_packet_server_data_u.domainGetInfoReply.nrVirtCpu = nrVirtCpu;
    }
    return 0;
}

static int qemudDispatchDomainSave(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.domainSaveRequest.file[PATH_MAX-1] ='\0';

    int ret = qemudDomainSave(server,
                              in->qemud_packet_client_data_u.domainSaveRequest.id,
                              in->qemud_packet_client_data_u.domainSaveRequest.file);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SAVE;
    }
    return 0;
}

static int qemudDispatchDomainRestore(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int id;

    /* Paranoia null termination */
    in->qemud_packet_client_data_u.domainRestoreRequest.file[PATH_MAX-1] ='\0';

    id = qemudDomainRestore(server, in->qemud_packet_client_data_u.domainRestoreRequest.file);
    if (id < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_RESTORE;
        out->qemud_packet_server_data_u.domainRestoreReply.id = id;
    }
    return 0;
}

static int qemudDispatchDumpXML(struct qemud_server *server, struct qemud_client *client,
                                struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret;
    ret = qemudDomainDumpXML(server,
                             in->qemud_packet_client_data_u.domainDumpXMLRequest.uuid,
                             out->qemud_packet_server_data_u.domainDumpXMLReply.xml,
                             QEMUD_MAX_XML_LEN);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DUMP_XML;
    }
    return 0;
}

static int qemudDispatchListDefinedDomains(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i, ndomains;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_DOMAINS)))
        return -1;

    for (i = 0 ; i < QEMUD_MAX_NUM_DOMAINS ; i++) {
        names[i] = &out->qemud_packet_server_data_u.listDefinedDomainsReply.domains[i*QEMUD_MAX_NAME_LEN];
    }

    ndomains = qemudListDefinedDomains(server,
                                       names,
                                       QEMUD_MAX_NUM_DOMAINS);
    free(names);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_DEFINED_DOMAINS;
        out->qemud_packet_server_data_u.listDefinedDomainsReply.numDomains = ndomains;
    }
    printf("%d %d\n", out->type, out->qemud_packet_server_data_u.listDefinedDomainsReply.numDomains);
    for (i = 0 ; i < ndomains;i++) {
        printf("[%s]\n", &out->qemud_packet_server_data_u.listDefinedDomainsReply.domains[i*QEMUD_MAX_NAME_LEN]);
    }
    return 0;
}

static int qemudDispatchNumDefinedDomains(struct qemud_server *server, struct qemud_client *client,
                                          struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int ndomains = qemudNumDefinedDomains(server);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DEFINED_DOMAINS;
        out->qemud_packet_server_data_u.numDefinedDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainStart(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_vm *vm;

    if (!(vm = qemudDomainStart(server, in->qemud_packet_client_data_u.domainStartRequest.uuid))) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_START;
        out->qemud_packet_server_data_u.domainStartReply.id = vm->id;
    }
    return 0;
}

static int qemudDispatchDomainDefine(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.domainDefineRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_vm *vm = qemudDomainDefine(server, in->qemud_packet_client_data_u.domainDefineRequest.xml);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_DEFINE;
        memcpy(out->qemud_packet_server_data_u.domainDefineReply.uuid, vm->def->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.domainDefineReply.name, vm->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.domainDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainUndefine(struct qemud_server *server, struct qemud_client *client,
                                       struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudDomainUndefine(server, in->qemud_packet_client_data_u.domainUndefineRequest.uuid);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_UNDEFINE;
    }
    return 0;
}

static int qemudDispatchNumNetworks(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int nnetworks = qemudNumNetworks(server);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_NETWORKS;
        out->qemud_packet_server_data_u.numNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchListNetworks(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_NETWORKS)))
        return -1;

    for (i = 0 ; i < QEMUD_MAX_NUM_NETWORKS ; i++) {
        names[i] = &out->qemud_packet_server_data_u.listNetworksReply.networks[i*QEMUD_MAX_NAME_LEN];
    }

    int nnetworks = qemudListNetworks(server,
                                      names,
                                      QEMUD_MAX_NUM_NETWORKS);
    free(names);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_NETWORKS;
        out->qemud_packet_server_data_u.listNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchNumDefinedNetworks(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    int nnetworks = qemudNumDefinedNetworks(server);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NUM_DEFINED_NETWORKS;
        out->qemud_packet_server_data_u.numDefinedNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchListDefinedNetworks(struct qemud_server *server, struct qemud_client *client,
                                            struct qemud_packet_client_data *in ATTRIBUTE_UNUSED, struct qemud_packet_server_data *out) {
    char **names;
    int i;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_NETWORKS)))
        return -1;

    for (i = 0 ; i < QEMUD_MAX_NUM_NETWORKS ; i++) {
        names[i] = &out->qemud_packet_server_data_u.listDefinedNetworksReply.networks[i*QEMUD_MAX_NAME_LEN];
    }

    int nnetworks = qemudListDefinedNetworks(server,
                                             names,
                                             QEMUD_MAX_NUM_NETWORKS);
    free(names);
    if (nnetworks < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_LIST_DEFINED_NETWORKS;
        out->qemud_packet_server_data_u.listDefinedNetworksReply.numNetworks = nnetworks;
    }
    return 0;
}

static int qemudDispatchNetworkLookupByName(struct qemud_server *server, struct qemud_client *client,
                                            struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    /* Paranoia NULL termination */
    in->qemud_packet_client_data_u.networkLookupByNameRequest.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    struct qemud_network *network = qemudFindNetworkByName(server, in->qemud_packet_client_data_u.networkLookupByNameRequest.name);
    if (!network) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_NAME;
        memcpy(out->qemud_packet_server_data_u.networkLookupByNameReply.uuid, network->def->uuid, QEMUD_UUID_RAW_LEN);
    }
    return 0;
}

static int qemudDispatchNetworkLookupByUUID(struct qemud_server *server, struct qemud_client *client,
                                            struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, in->qemud_packet_client_data_u.networkLookupByUUIDRequest.uuid);
    if (!network) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_LOOKUP_BY_UUID;
        strncpy(out->qemud_packet_server_data_u.networkLookupByUUIDReply.name, network->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchNetworkCreate(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.networkCreateRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_network *network = qemudNetworkCreate(server, in->qemud_packet_client_data_u.networkCreateRequest.xml);
    if (!network) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_CREATE;
        memcpy(out->qemud_packet_server_data_u.networkCreateReply.uuid, network->def->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.networkCreateReply.name, network->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchNetworkDefine(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    in->qemud_packet_client_data_u.networkDefineRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_network *network = qemudNetworkDefine(server, in->qemud_packet_client_data_u.networkDefineRequest.xml);
    if (!network) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DEFINE;
        memcpy(out->qemud_packet_server_data_u.networkDefineReply.uuid, network->def->uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->qemud_packet_server_data_u.networkDefineReply.name, network->def->name, QEMUD_MAX_NAME_LEN-1);
        out->qemud_packet_server_data_u.networkDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchNetworkUndefine(struct qemud_server *server, struct qemud_client *client,
                                        struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudNetworkUndefine(server, in->qemud_packet_client_data_u.networkUndefineRequest.uuid);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_UNDEFINE;
    }
    return 0;
}

static int qemudDispatchNetworkStart(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    struct qemud_network *network;

    if (!(network = qemudNetworkStart(server, in->qemud_packet_client_data_u.networkStartRequest.uuid))) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_START;
    }
    return 0;
}

static int qemudDispatchNetworkDestroy(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    if (qemudNetworkDestroy(server, in->qemud_packet_client_data_u.networkDestroyRequest.uuid) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DESTROY;
    }
    return 0;
}

static int qemudDispatchNetworkDumpXML(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudNetworkDumpXML(server,
                                  in->qemud_packet_client_data_u.networkDumpXMLRequest.uuid,
                                  out->qemud_packet_server_data_u.networkDumpXMLReply.xml, QEMUD_MAX_XML_LEN);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_DUMP_XML;
    }
    return 0;
}

static int qemudDispatchNetworkGetBridgeName(struct qemud_server *server, struct qemud_client *client,
                                             struct qemud_packet_client_data *in, struct qemud_packet_server_data *out) {
    int ret = qemudNetworkGetBridgeName(server,
                                        in->qemud_packet_client_data_u.networkDumpXMLRequest.uuid,
                                        out->qemud_packet_server_data_u.networkGetBridgeNameReply.ifname, QEMUD_MAX_IFNAME_LEN);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_GET_BRIDGE_NAME;
    }
    return 0;
}

static int qemudDispatchDomainGetAutostart(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in, struct qemud_packet_server_data *out)
{
    int ret;
    int autostart;

    autostart = 0;

    ret = qemudDomainGetAutostart(server,
                                  in->qemud_packet_client_data_u.domainGetAutostartRequest.uuid,
                                  &autostart);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_GET_AUTOSTART;
        out->qemud_packet_server_data_u.networkGetAutostartReply.autostart = (autostart != 0);
    }
    return 0;
}

static int qemudDispatchDomainSetAutostart(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet_client_data *in, struct qemud_packet_server_data *out)
{
    int ret;

    ret = qemudDomainSetAutostart(server,
                                  in->qemud_packet_client_data_u.domainGetAutostartRequest.uuid,
                                  in->qemud_packet_client_data_u.domainSetAutostartRequest.autostart);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_DOMAIN_SET_AUTOSTART;
    }
    return 0;
}

static int qemudDispatchNetworkGetAutostart(struct qemud_server *server, struct qemud_client *client,
                                            struct qemud_packet_client_data *in, struct qemud_packet_server_data *out)
{
    int ret;
    int autostart;

    autostart = 0;

    ret = qemudNetworkGetAutostart(server,
                                   in->qemud_packet_client_data_u.networkGetAutostartRequest.uuid,
                                   &autostart);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_GET_AUTOSTART;
        out->qemud_packet_server_data_u.networkGetAutostartReply.autostart = (autostart != 0);
    }
    return 0;
}

static int qemudDispatchNetworkSetAutostart(struct qemud_server *server, struct qemud_client *client,
                                            struct qemud_packet_client_data *in, struct qemud_packet_server_data *out)
{
    int ret;

    ret = qemudNetworkSetAutostart(server,
                                   in->qemud_packet_client_data_u.networkGetAutostartRequest.uuid,
                                   in->qemud_packet_client_data_u.networkSetAutostartRequest.autostart);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->type = QEMUD_SERVER_PKT_NETWORK_SET_AUTOSTART;
    }
    return 0;
}

typedef int (*clientFunc)(struct qemud_server *server, struct qemud_client *client,
                          struct qemud_packet_client_data *in, struct qemud_packet_server_data *out);


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
int qemudDispatch(struct qemud_server *server, struct qemud_client *client,
                  qemud_packet_client_data *in, qemud_packet_server_data *out) {
    clientFunc *funcs;
    unsigned int type = in->type;
    qemudDebug("> Dispatching request type %d, readonly ? %d",
               in->type, client->readonly);

    server->errorCode = 0;
    server->errorMessage[0] = '\0';

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
        qemudReportError(server, VIR_ERR_OPERATION_DENIED, NULL);
        qemudDispatchFailure(server, client, out);
    } else {
        if ((funcs[type])(server, client, in, out) < 0) {
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
