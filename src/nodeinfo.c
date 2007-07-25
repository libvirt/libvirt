/*
 * nodeinfo.c: Helper routines for OS specific node information
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <errno.h>
#include <ctype.h>

#include "nodeinfo.h"

#ifdef __linux__
#define MEMINFO_PATH "/proc/meminfo"
#define CPUINFO_PATH "/proc/cpuinfo"

/* NB, these are not static as we need to call them from testsuite */
int linuxNodeInfoCPUPopulate(virConnectPtr conn, FILE *cpuinfo, virNodeInfoPtr nodeinfo);
int linuxNodeInfoMemPopulate(virConnectPtr conn, FILE *meminfo, virNodeInfoPtr nodeinfo);

int linuxNodeInfoCPUPopulate(virConnectPtr conn, FILE *cpuinfo, virNodeInfoPtr nodeinfo) {
    char line[1024];

    nodeinfo->cpus = 0;
    nodeinfo->mhz = 0;
    nodeinfo->nodes = nodeinfo->sockets = nodeinfo->cores = nodeinfo->threads = 1;

    /* NB: It is impossible to fill our nodes, since cpuinfo
     * has not knowledge of NUMA nodes */

    /* XXX hyperthreads */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        char *buf = line;
        if (STREQLEN(buf, "processor", 9)) { /* aka a single logical CPU */
            buf += 9;
            while (*buf && isspace(*buf))
                buf++;
            if (*buf != ':') {
                __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                                VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                                "parsing cpuinfo processor");
                return -1;
            }
            nodeinfo->cpus++;
        } else if (STREQLEN(buf, "cpu MHz", 7)) {
            buf += 9;
            while (*buf && isspace(*buf))
                buf++;
            if (*buf != ':' || !buf[1]) {
                __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                                VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                                "parsing cpuinfo cpu MHz");
                return -1;
            }
            nodeinfo->mhz = (unsigned int)strtol(buf+1, NULL, 10);
        } else if (STREQLEN(buf, "cpu cores", 9)) { /* aka cores */
            unsigned int id;
            buf += 9;
            while (*buf && isspace(*buf))
                buf++;
            if (*buf != ':' || !buf[1]) {
                __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                                VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                                "parsing cpuinfo cpu cores %c", *buf);
                return -1;
            }
            id = (unsigned int)strtol(buf+1, NULL, 10);
            if (id > nodeinfo->cores)
                nodeinfo->cores = id;
        }
    }

    if (!nodeinfo->cpus) {
        __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                        VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                        "no cpus found");
        return -1;
    }

    /*
     * Can't reliably count sockets from proc metadata, so
     * infer it based on total CPUs vs cores.
     * XXX hyperthreads
     */
    nodeinfo->sockets = nodeinfo->cpus / nodeinfo->cores;

    return 0;
}


int linuxNodeInfoMemPopulate(virConnectPtr conn, FILE *meminfo, virNodeInfoPtr nodeinfo) {
    char line[1024];

    nodeinfo->memory = 0;

    while (fgets(line, sizeof(line), meminfo) != NULL) {
        if (STREQLEN(line, "MemTotal:", 9)) {
            nodeinfo->memory = (unsigned int)strtol(line + 10, NULL, 10);
        }
    }
    if (!nodeinfo->memory) {
        __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                        VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                        "no memory found");
        return -1;
    }

    return 0;
}


#endif

int virNodeInfoPopulate(virConnectPtr conn,
                        virNodeInfoPtr nodeinfo) {
    struct utsname info;
#ifdef __linux__
    int ret;
    FILE *cpuinfo, *meminfo;
#endif

    if (uname(&info) < 0) {
        __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                        VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                        "cannot extract machine type %s", strerror(errno));
        return -1;
    }

    strncpy(nodeinfo->model, info.machine, sizeof(nodeinfo->model)-1);
    nodeinfo->model[sizeof(nodeinfo->model)-1] = '\0';

#ifdef __linux__
    cpuinfo = fopen(CPUINFO_PATH, "r");
    if (!cpuinfo) {
        __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                        VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                        "cannot open %s %s", CPUINFO_PATH, strerror(errno));
        return -1;
    }
    ret = linuxNodeInfoCPUPopulate(conn, cpuinfo, nodeinfo);
    fclose(cpuinfo);
    if (ret < 0)
        return -1;

    meminfo = fopen(MEMINFO_PATH, "r");
    if (!meminfo) {
        __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                        VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                        "cannot open %s %s", MEMINFO_PATH, strerror(errno));
        return -1;
    }
    ret = linuxNodeInfoMemPopulate(conn, meminfo, nodeinfo);
    fclose(meminfo);

    return ret;
#else
    /* XXX Solaris will need an impl later if they port QEMU driver */
    __virRaiseError(conn, NULL, NULL, 0, VIR_ERR_INTERNAL_ERROR,
                    VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                    "%s:%s not implemented on this platform\n", __FILE__, __FUNCTION__);
    return -1;
#endif
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
