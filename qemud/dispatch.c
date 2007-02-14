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

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <libvirt/virterror.h>

#include "internal.h"
#include "driver.h"
#include "dispatch.h"


static int qemudDispatchFailure(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                struct qemud_packet *out) {
    out->header.type = QEMUD_PKT_FAILURE;
    out->header.dataSize = sizeof(out->data.failureReply);
    out->data.failureReply.code = server->errorCode;
    strcpy(out->data.failureReply.message, server->errorMessage);
    return 0;
}


static int qemudDispatchGetVersion(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != 0)
        return -1;

    int version = qemudGetVersion(server);
    if (version < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_GET_VERSION;
        out->header.dataSize = sizeof(out->data.getVersionReply);
        out->data.getVersionReply.version = version;
    }
    return 0;
}

static int qemudDispatchGetNodeInfo(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet *in, struct qemud_packet *out) {
    struct utsname info;

    if (in->header.dataSize != 0)
        return -1;

    if (uname(&info) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
        return 0;
    }

    if (qemudGetCPUInfo(&out->data.getNodeInfoReply.cpus,
                        &out->data.getNodeInfoReply.mhz,
                        &out->data.getNodeInfoReply.nodes,
                        &out->data.getNodeInfoReply.sockets,
                        &out->data.getNodeInfoReply.cores,
                        &out->data.getNodeInfoReply.threads) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
        return 0;
    }
    if (qemudGetMemInfo(&out->data.getNodeInfoReply.memory) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
        return 0;
    }

    out->header.type = QEMUD_PKT_GET_NODEINFO;
    out->header.dataSize = sizeof(out->data.getNodeInfoReply);
    strncpy(out->data.getNodeInfoReply.model, info.machine, sizeof(out->data.getNodeInfoReply.model));
    out->data.getNodeInfoReply.model[sizeof(out->data.getNodeInfoReply.model)-1] = '\0';

    return 0;
}

static int qemudDispatchListDomains(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet *in, struct qemud_packet *out) {
    int i, ndomains, domains[QEMUD_MAX_NUM_DOMAINS];
    if (in->header.dataSize != 0)
        return -1;

    ndomains = qemudListDomains(server,
                                domains,
                                QEMUD_MAX_NUM_DOMAINS);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_LIST_DOMAINS;
        out->header.dataSize = sizeof(out->data.listDomainsReply);
        for (i = 0 ; i < ndomains ; i++) {
            out->data.listDomainsReply.domains[i] = domains[i];
        }
        out->data.listDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchNumDomains(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != 0)
        return -1;

    int ndomains = qemudNumDomains(server);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_NUM_DOMAINS;
        out->header.dataSize = sizeof(out->data.numDomainsReply);
        out->data.numDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainCreate(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainCreateRequest))
        return -1;

    in->data.domainCreateRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_vm *vm = qemudDomainCreate(server, in->data.domainCreateRequest.xml);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_CREATE;
        out->header.dataSize = sizeof(out->data.domainCreateReply);
        out->data.domainCreateReply.id = vm->def.id;
        memcpy(out->data.domainCreateReply.uuid, vm->def.uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->data.domainCreateReply.name, vm->def.name, QEMUD_MAX_NAME_LEN-1);
        out->data.domainCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByID(struct qemud_server *server, struct qemud_client *client,
                                         struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainLookupByIDRequest))
        return -1;

    struct qemud_vm *vm = qemudFindVMByID(server, in->data.domainLookupByIDRequest.id);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_ID;
        out->header.dataSize = sizeof(out->data.domainLookupByIDReply);
        memcpy(out->data.domainLookupByIDReply.uuid, vm->def.uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->data.domainLookupByIDReply.name, vm->def.name, QEMUD_MAX_NAME_LEN-1);
        out->data.domainLookupByIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByUUID(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainLookupByUUIDRequest))
        return -1;

    struct qemud_vm *vm = qemudFindVMByUUID(server, in->data.domainLookupByUUIDRequest.uuid);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_UUID;
        out->header.dataSize = sizeof(out->data.domainLookupByUUIDReply);
        out->data.domainLookupByUUIDReply.id = vm->def.id;
        strncpy(out->data.domainLookupByUUIDReply.name, vm->def.name, QEMUD_MAX_NAME_LEN-1);
        out->data.domainLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainLookupByName(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainLookupByNameRequest))
        return -1;

    /* Paranoia NULL termination */
    in->data.domainLookupByNameRequest.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    struct qemud_vm *vm = qemudFindVMByName(server, in->data.domainLookupByNameRequest.name);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_NAME;
        out->header.dataSize = sizeof(out->data.domainLookupByNameReply);
        out->data.domainLookupByNameReply.id = vm->def.id;
        memcpy(out->data.domainLookupByNameReply.uuid, vm->def.uuid, QEMUD_UUID_RAW_LEN);
    }
    return 0;
}

static int qemudDispatchDomainSuspend(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainSuspendRequest))
        return -1;

    int ret = qemudDomainSuspend(server, in->data.domainSuspendRequest.id);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_SUSPEND;
        out->header.dataSize = 0;
    }
    return 0;
}

static int qemudDispatchDomainResume(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainResumeRequest))
        return -1;

    int ret = qemudDomainResume(server, in->data.domainResumeRequest.id);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_RESUME;
        out->header.dataSize = 0;
    }
    return 0;
}

static int qemudDispatchDomainDestroy(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainDestroyRequest))
        return -1;

    int ret = qemudDomainDestroy(server, in->data.domainDestroyRequest.id);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_DESTROY;
        out->header.dataSize = 0;
    }
    return 0;
}

static int qemudDispatchDomainGetInfo(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet *in, struct qemud_packet *out) {
    int runstate;
    unsigned long long cpuTime;
    unsigned long memory;
    unsigned long maxmem;
    unsigned int nrVirtCpu;

    if (in->header.dataSize != sizeof(in->data.domainGetInfoRequest))
        return -1;

    int ret = qemudDomainGetInfo(server, in->data.domainGetInfoRequest.uuid,
                                 &runstate,
                                 &cpuTime,
                                 &maxmem,
                                 &memory,
                                 &nrVirtCpu);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_GET_INFO;
        out->header.dataSize = sizeof(out->data.domainGetInfoReply);
        out->data.domainGetInfoReply.runstate = runstate;
        out->data.domainGetInfoReply.cpuTime = cpuTime;
        out->data.domainGetInfoReply.maxmem = maxmem;
        out->data.domainGetInfoReply.memory = memory;
        out->data.domainGetInfoReply.nrVirtCpu = nrVirtCpu;
    }
    return 0;
}

static int qemudDispatchDomainSave(struct qemud_server *server, struct qemud_client *client,
                                   struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainSaveRequest))
        return -1;

    /* Paranoia NULL termination */
    in->data.domainSaveRequest.file[PATH_MAX-1] ='\0';

    int ret = qemudDomainSave(server,
                              in->data.domainSaveRequest.id,
                              in->data.domainSaveRequest.file);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_SAVE;
        out->header.dataSize = 0;
    }
    return 0;
}

static int qemudDispatchDomainRestore(struct qemud_server *server, struct qemud_client *client,
                                      struct qemud_packet *in, struct qemud_packet *out) {
    int id;
    if (in->header.dataSize != sizeof(in->data.domainRestoreRequest))
        return -1;

    /* Paranoia null termination */
    in->data.domainRestoreRequest.file[PATH_MAX-1] ='\0';

    id = qemudDomainRestore(server, in->data.domainRestoreRequest.file);
    if (id < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_RESTORE;
        out->header.dataSize = sizeof(out->data.domainRestoreReply);
        out->data.domainRestoreReply.id = id;
    }
    return 0;
}

static int qemudDispatchDumpXML(struct qemud_server *server, struct qemud_client *client,
                                struct qemud_packet *in, struct qemud_packet *out) {
    int ret;
    if (in->header.dataSize != sizeof(in->data.domainDumpXMLRequest))
        return -1;

    ret = qemudDomainDumpXML(server,
                             in->data.domainDumpXMLRequest.uuid,
                             out->data.domainDumpXMLReply.xml,
                             QEMUD_MAX_XML_LEN);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DUMP_XML;
        out->header.dataSize = sizeof(out->data.domainDumpXMLReply);
    }
    return 0;
}

static int qemudDispatchListDefinedDomains(struct qemud_server *server, struct qemud_client *client,
                                           struct qemud_packet *in, struct qemud_packet *out) {
    char **names;
    int i, ndomains;
    if (in->header.dataSize != 0)
        return -1;

    if (!(names = malloc(sizeof(char *)*QEMUD_MAX_NUM_DOMAINS)))
        return -1;

    for (i = 0 ; i < QEMUD_MAX_NUM_DOMAINS ; i++) {
        names[i] = out->data.listDefinedDomainsReply.domains[i];
    }

    ndomains = qemudListDefinedDomains(server,
                                       names,
                                       QEMUD_MAX_NUM_DOMAINS);
    free(names);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_LIST_DEFINED_DOMAINS;
        out->header.dataSize = sizeof(out->data.listDefinedDomainsReply);
        out->data.listDefinedDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchNumDefinedDomains(struct qemud_server *server, struct qemud_client *client,
                                          struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != 0)
        return -1;

    int ndomains = qemudNumDefinedDomains(server);
    if (ndomains < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_NUM_DEFINED_DOMAINS;
        out->header.dataSize = sizeof(out->data.numDefinedDomainsReply);
        out->data.numDefinedDomainsReply.numDomains = ndomains;
    }
    return 0;
}

static int qemudDispatchDomainStart(struct qemud_server *server, struct qemud_client *client,
                                    struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainStartRequest))
        return -1;

    struct qemud_vm *vm = qemudFindVMByUUID(server, in->data.domainStartRequest.uuid);
    if (!vm || qemudDomainStart(server, vm) < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_START;
        out->header.dataSize = sizeof(out->data.domainStartReply);
        out->data.domainStartReply.id = vm->def.id;
    }
    return 0;
}

static int qemudDispatchDomainDefine(struct qemud_server *server, struct qemud_client *client,
                                     struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainDefineRequest))
        return -1;

    in->data.domainDefineRequest.xml[QEMUD_MAX_XML_LEN-1] ='\0';

    struct qemud_vm *vm = qemudDomainDefine(server, in->data.domainDefineRequest.xml);
    if (!vm) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_DEFINE;
        out->header.dataSize = sizeof(out->data.domainDefineReply);
        memcpy(out->data.domainDefineReply.uuid, vm->def.uuid, QEMUD_UUID_RAW_LEN);
        strncpy(out->data.domainDefineReply.name, vm->def.name, QEMUD_MAX_NAME_LEN-1);
        out->data.domainDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';
    }
    return 0;
}

static int qemudDispatchDomainUndefine(struct qemud_server *server, struct qemud_client *client,
                                       struct qemud_packet *in, struct qemud_packet *out) {
    if (in->header.dataSize != sizeof(in->data.domainUndefineRequest))
        return -1;

    int ret = qemudDomainUndefine(server, in->data.domainUndefineRequest.uuid);
    if (ret < 0) {
        if (qemudDispatchFailure(server, client, out) < 0)
            return -1;
    } else {
        out->header.type = QEMUD_PKT_DOMAIN_UNDEFINE;
        out->header.dataSize = 0;
    }
    return 0;
}


typedef int (*clientFunc)(struct qemud_server *server, struct qemud_client *client,
                          struct qemud_packet *in, struct qemud_packet *out);


/* One per message type recorded in qemud_packet_type enum */

clientFunc funcsTransmitRW[QEMUD_PKT_MAX] = {
    NULL, /* FAILURE code */
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
    qemudDispatchDomainUndefine
};

clientFunc funcsTransmitRO[QEMUD_PKT_MAX] = {
    NULL, /* FAILURE code */
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
                  struct qemud_packet *in, struct qemud_packet *out) {
    clientFunc *funcs;
    unsigned int type = in->header.type;
    QEMUD_DEBUG("> Dispatching request %d readonly ? %d\n", type, client->readonly);

    server->errorCode = 0;
    server->errorMessage[0] = '\0';

    memset(out, 0, sizeof(struct qemud_packet));

    if (type >= QEMUD_PKT_MAX) {
        QEMUD_DEBUG("Illegal request type\n");
        return -1;
    }

    if (type == QEMUD_PKT_FAILURE) {
        QEMUD_DEBUG("Illegal request type\n");
        return -1;
    }

    if (client->readonly)
        funcs = funcsTransmitRO;
    else
        funcs = funcsTransmitRW;

    if (!funcs[type]) {
        QEMUD_DEBUG("Illegal operation requested\n");
        qemudReportError(server, VIR_ERR_OPERATION_DENIED, NULL);
        qemudDispatchFailure(server, client, out);
    } else {
        if ((funcs[type])(server, client, in, out) < 0) {
            QEMUD_DEBUG("Dispatch failed\n");
            return -1;
        }
    }

    QEMUD_DEBUG("< Returning reply %d (%d bytes)\n",
           out->header.type,
           out->header.dataSize);

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
