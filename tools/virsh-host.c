/*
 * virsh-host.c: Commands in "Host and Hypervisor" group.
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

/*
 * "capabilities" command
 */
static const vshCmdInfo info_capabilities[] = {
    {"help", N_("capabilities")},
    {"desc", N_("Returns capabilities of hypervisor/driver.")},
    {NULL, NULL}
};

static bool
cmdCapabilities(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if ((caps = virConnectGetCapabilities(ctl->conn)) == NULL) {
        vshError(ctl, "%s", _("failed to get capabilities"));
        return false;
    }
    vshPrint(ctl, "%s\n", caps);
    VIR_FREE(caps);

    return true;
}

/*
 * "connect" command
 */
static const vshCmdInfo info_connect[] = {
    {"help", N_("(re)connect to hypervisor")},
    {"desc",
     N_("Connect to local hypervisor. This is built-in command after shell start up.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_connect[] = {
    {"name",     VSH_OT_DATA, VSH_OFLAG_EMPTY_OK,
     N_("hypervisor connection URI")},
    {"readonly", VSH_OT_BOOL, 0, N_("read-only connection")},
    {NULL, 0, 0, NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ro = vshCommandOptBool(cmd, "readonly");
    const char *name = NULL;

    if (ctl->conn) {
        int ret;
        if ((ret = virConnectClose(ctl->conn)) != 0) {
            vshError(ctl, _("Failed to disconnect from the hypervisor, %d leaked reference(s)"), ret);
            return false;
        }
        ctl->conn = NULL;
    }

    VIR_FREE(ctl->name);
    if (vshCommandOptString(cmd, "name", &name) < 0) {
        vshError(ctl, "%s", _("Please specify valid connection URI"));
        return false;
    }
    ctl->name = vshStrdup(ctl, name);

    ctl->useGetInfo = false;
    ctl->useSnapshotOld = false;
    ctl->readonly = ro;

    ctl->conn = virConnectOpenAuth(ctl->name, virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);

    if (!ctl->conn)
        vshError(ctl, "%s", _("Failed to connect to the hypervisor"));

    return !!ctl->conn;
}

/*
 * "freecell" command
 */
static const vshCmdInfo info_freecell[] = {
    {"help", N_("NUMA free memory")},
    {"desc", N_("display available free memory for the NUMA cell.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_freecell[] = {
    {"cellno", VSH_OT_INT, 0, N_("NUMA cell number")},
    {"all", VSH_OT_BOOL, 0, N_("show free memory for all NUMA cells")},
    {NULL, 0, 0, NULL}
};

static bool
cmdFreecell(vshControl *ctl, const vshCmd *cmd)
{
    bool func_ret = false;
    int ret;
    int cell = -1, cell_given;
    unsigned long long memory;
    xmlNodePtr *nodes = NULL;
    unsigned long nodes_cnt;
    unsigned long *nodes_id = NULL;
    unsigned long long *nodes_free = NULL;
    int all_given;
    int i;
    char *cap_xml = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;


    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if ( (cell_given = vshCommandOptInt(cmd, "cellno", &cell)) < 0) {
        vshError(ctl, "%s", _("cell number has to be a number"));
        goto cleanup;
    }
    all_given = vshCommandOptBool(cmd, "all");

    if (all_given && cell_given) {
        vshError(ctl, "%s", _("--cellno and --all are mutually exclusive. "
                              "Please choose only one."));
        goto cleanup;
    }

    if (all_given) {
        cap_xml = virConnectGetCapabilities(ctl->conn);
        if (!cap_xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        xml = virXMLParseStringCtxt(cap_xml, _("(capabilities)"), &ctxt);
        if (!xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }
        nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell",
                                    ctxt, &nodes);

        if (nodes_cnt == -1) {
            vshError(ctl, "%s", _("could not get information about "
                                  "NUMA topology"));
            goto cleanup;
        }

        nodes_free = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_free));
        nodes_id = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_id));

        for (i = 0; i < nodes_cnt; i++) {
            unsigned long id;
            char *val = virXMLPropString(nodes[i], "id");
            if (virStrToLong_ul(val, NULL, 10, &id)) {
                vshError(ctl, "%s", _("conversion from string failed"));
                VIR_FREE(val);
                goto cleanup;
            }
            VIR_FREE(val);
            nodes_id[i]=id;
            ret = virNodeGetCellsFreeMemory(ctl->conn, &(nodes_free[i]), id, 1);
            if (ret != 1) {
                vshError(ctl, _("failed to get free memory for NUMA node "
                                "number: %lu"), id);
                goto cleanup;
            }
        }

        memory = 0;
        for (cell = 0; cell < nodes_cnt; cell++) {
            vshPrint(ctl, "%5lu: %10llu KiB\n", nodes_id[cell],
                    (nodes_free[cell]/1024));
            memory += nodes_free[cell];
        }

        vshPrintExtra(ctl, "--------------------\n");
        vshPrintExtra(ctl, "%5s: %10llu KiB\n", _("Total"), memory/1024);
    } else {
        if (!cell_given) {
            memory = virNodeGetFreeMemory(ctl->conn);
            if (memory == 0)
                goto cleanup;
        } else {
            ret = virNodeGetCellsFreeMemory(ctl->conn, &memory, cell, 1);
            if (ret != 1)
                goto cleanup;
        }

        if (cell == -1)
            vshPrint(ctl, "%s: %llu KiB\n", _("Total"), (memory/1024));
        else
            vshPrint(ctl, "%d: %llu KiB\n", cell, (memory/1024));
    }

    func_ret = true;

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(nodes);
    VIR_FREE(nodes_free);
    VIR_FREE(nodes_id);
    VIR_FREE(cap_xml);
    return func_ret;
}

/*
 * "nodeinfo" command
 */
static const vshCmdInfo info_nodeinfo[] = {
    {"help", N_("node information")},
    {"desc", N_("Returns basic information about the node.")},
    {NULL, NULL}
};

static bool
cmdNodeinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (virNodeGetInfo(ctl->conn, &info) < 0) {
        vshError(ctl, "%s", _("failed to get node information"));
        return false;
    }
    vshPrint(ctl, "%-20s %s\n", _("CPU model:"), info.model);
    vshPrint(ctl, "%-20s %d\n", _("CPU(s):"), info.cpus);
    vshPrint(ctl, "%-20s %d MHz\n", _("CPU frequency:"), info.mhz);
    vshPrint(ctl, "%-20s %d\n", _("CPU socket(s):"), info.sockets);
    vshPrint(ctl, "%-20s %d\n", _("Core(s) per socket:"), info.cores);
    vshPrint(ctl, "%-20s %d\n", _("Thread(s) per core:"), info.threads);
    vshPrint(ctl, "%-20s %d\n", _("NUMA cell(s):"), info.nodes);
    vshPrint(ctl, "%-20s %lu KiB\n", _("Memory size:"), info.memory);

    return true;
}

/*
 * "nodecpustats" command
 */
static const vshCmdInfo info_nodecpustats[] = {
    {"help", N_("Prints cpu stats of the node.")},
    {"desc", N_("Returns cpu stats of the node, in nanoseconds.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_cpustats[] = {
    {"cpu", VSH_OT_INT, 0, N_("prints specified cpu statistics only.")},
    {"percent", VSH_OT_BOOL, 0, N_("prints by percentage during 1 second.")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeCpuStats(vshControl *ctl, const vshCmd *cmd)
{
    int i, j;
    bool flag_utilization = false;
    bool flag_percent = vshCommandOptBool(cmd, "percent");
    int cpuNum = VIR_NODE_CPU_STATS_ALL_CPUS;
    virNodeCPUStatsPtr params;
    int nparams = 0;
    bool ret = false;
    struct cpu_stats {
        unsigned long long user;
        unsigned long long sys;
        unsigned long long idle;
        unsigned long long iowait;
        unsigned long long util;
    } cpu_stats[2];
    double user_time, sys_time, idle_time, iowait_time, total_time;
    double usage;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptInt(cmd, "cpu", &cpuNum) < 0) {
        vshError(ctl, "%s", _("Invalid value of cpuNum"));
        return false;
    }

    if (virNodeGetCPUStats(ctl->conn, cpuNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of cpu stats"));
        return false;
    }
    if (nparams == 0) {
        /* nothing to output */
        return true;
    }

    memset(cpu_stats, 0, sizeof(cpu_stats));
    params = vshCalloc(ctl, nparams, sizeof(*params));

    for (i = 0; i < 2; i++) {
        if (i > 0)
            sleep(1);

        if (virNodeGetCPUStats(ctl->conn, cpuNum, params, &nparams, 0) != 0) {
            vshError(ctl, "%s", _("Unable to get node cpu stats"));
            goto cleanup;
        }

        for (j = 0; j < nparams; j++) {
            unsigned long long value = params[j].value;

            if (STREQ(params[j].field, VIR_NODE_CPU_STATS_KERNEL)) {
                cpu_stats[i].sys = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_USER)) {
                cpu_stats[i].user = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_IDLE)) {
                cpu_stats[i].idle = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_IOWAIT)) {
                cpu_stats[i].iowait = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_UTILIZATION)) {
                cpu_stats[i].util = value;
                flag_utilization = true;
            }
        }

        if (flag_utilization || !flag_percent)
            break;
    }

    if (!flag_percent) {
        if (!flag_utilization) {
            vshPrint(ctl, "%-15s %20llu\n", _("user:"), cpu_stats[0].user);
            vshPrint(ctl, "%-15s %20llu\n", _("system:"), cpu_stats[0].sys);
            vshPrint(ctl, "%-15s %20llu\n", _("idle:"), cpu_stats[0].idle);
            vshPrint(ctl, "%-15s %20llu\n", _("iowait:"), cpu_stats[0].iowait);
        }
    } else {
        if (flag_utilization) {
            usage = cpu_stats[0].util;

            vshPrint(ctl, "%-15s %5.1lf%%\n", _("usage:"), usage);
            vshPrint(ctl, "%-15s %5.1lf%%\n", _("idle:"), 100 - usage);
        } else {
            user_time   = cpu_stats[1].user   - cpu_stats[0].user;
            sys_time    = cpu_stats[1].sys    - cpu_stats[0].sys;
            idle_time   = cpu_stats[1].idle   - cpu_stats[0].idle;
            iowait_time = cpu_stats[1].iowait - cpu_stats[0].iowait;
            total_time  = user_time + sys_time + idle_time + iowait_time;

            usage = (user_time + sys_time) / total_time * 100;

            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("usage:"), usage);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("user:"), user_time / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("system:"), sys_time  / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("idle:"), idle_time     / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("iowait:"), iowait_time   / total_time * 100);
        }
    }

    ret = true;

  cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodememstats" command
 */
static const vshCmdInfo info_nodememstats[] = {
    {"help", N_("Prints memory stats of the node.")},
    {"desc", N_("Returns memory stats of the node, in kilobytes.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_memstats[] = {
    {"cell", VSH_OT_INT, 0, N_("prints specified cell statistics only.")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeMemStats(vshControl *ctl, const vshCmd *cmd)
{
    int nparams = 0;
    unsigned int i = 0;
    int cellNum = VIR_NODE_MEMORY_STATS_ALL_CELLS;
    virNodeMemoryStatsPtr params = NULL;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptInt(cmd, "cell", &cellNum) < 0) {
        vshError(ctl, "%s", _("Invalid value of cellNum"));
        return false;
    }

    /* get the number of memory parameters */
    if (virNodeGetMemoryStats(ctl->conn, cellNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of memory stats"));
        goto cleanup;
    }

    if (nparams == 0) {
        /* nothing to output */
        ret = true;
        goto cleanup;
    }

    /* now go get all the memory parameters */
    params = vshCalloc(ctl, nparams, sizeof(*params));
    if (virNodeGetMemoryStats(ctl->conn, cellNum, params, &nparams, 0) != 0) {
        vshError(ctl, "%s", _("Unable to get memory stats"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++)
        vshPrint(ctl, "%-7s: %20llu KiB\n", params[i].field, params[i].value);

    ret = true;

  cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodesuspend" command
 */
static const vshCmdInfo info_nodesuspend[] = {
    {"help", N_("suspend the host node for a given time duration")},
    {"desc", N_("Suspend the host node for a given time duration "
                               "and attempt to resume thereafter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_suspend[] = {
    {"target", VSH_OT_DATA, VSH_OFLAG_REQ, N_("mem(Suspend-to-RAM), "
                                               "disk(Suspend-to-Disk), hybrid(Hybrid-Suspend)")},
    {"duration", VSH_OT_INT, VSH_OFLAG_REQ, N_("Suspend duration in seconds, at least 60")},
    {"flags", VSH_OT_INT, VSH_OFLAG_NONE, N_("Suspend flags, 0 for default")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeSuspend(vshControl *ctl, const vshCmd *cmd)
{
    const char *target = NULL;
    unsigned int suspendTarget;
    long long duration;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "target", &target) < 0) {
        vshError(ctl, _("Invalid target argument"));
        return false;
    }

    if (vshCommandOptLongLong(cmd, "duration", &duration) < 0) {
        vshError(ctl, _("Invalid duration argument"));
        return false;
    }

    if (vshCommandOptUInt(cmd, "flags", &flags) < 0) {
        vshError(ctl, _("Invalid flags argument"));
        return false;
    }

    if (STREQ(target, "mem"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    else if (STREQ(target, "disk"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    else if (STREQ(target, "hybrid"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    else {
        vshError(ctl, "%s", _("Invalid target"));
        return false;
    }

    if (duration <= 0) {
        vshError(ctl, "%s", _("Invalid duration"));
        return false;
    }

    if (virNodeSuspendForDuration(ctl->conn, suspendTarget, duration,
                                  flags) < 0) {
        vshError(ctl, "%s", _("The host was not suspended"));
        return false;
    }
    return true;
}

/*
 * "qemu-monitor-command" command
 */
static const vshCmdInfo info_qemu_monitor_command[] = {
    {"help", N_("QEMU Monitor Command")},
    {"desc", N_("QEMU Monitor Command")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_qemu_monitor_command[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"hmp", VSH_OT_BOOL, 0, N_("command is in human monitor protocol")},
    {"cmd", VSH_OT_ARGV, VSH_OFLAG_REQ, N_("command")},
    {NULL, 0, 0, NULL}
};

static bool
cmdQemuMonitorCommand(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *monitor_cmd = NULL;
    char *result = NULL;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool pad = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        if (pad)
            virBufferAddChar(&buf, ' ');
        pad = true;
        virBufferAdd(&buf, opt->data, -1);
    }
    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to collect command"));
        goto cleanup;
    }
    monitor_cmd = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "hmp"))
        flags |= VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP;

    if (virDomainQemuMonitorCommand(dom, monitor_cmd, &result, flags) < 0)
        goto cleanup;

    printf("%s\n", result);

    ret = true;

cleanup:
    VIR_FREE(result);
    VIR_FREE(monitor_cmd);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "qemu-attach" command
 */
static const vshCmdInfo info_qemu_attach[] = {
    {"help", N_("QEMU Attach")},
    {"desc", N_("QEMU Attach")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_qemu_attach[] = {
    {"pid", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdQemuAttach(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    unsigned int pid_value; /* API uses unsigned int, not pid_t */

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (vshCommandOptUInt(cmd, "pid", &pid_value) <= 0) {
        vshError(ctl, "%s", _("missing pid value"));
        goto cleanup;
    }

    if (!(dom = virDomainQemuAttach(ctl->conn, pid_value, flags)))
        goto cleanup;

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s attached to pid %u\n"),
                 virDomainGetName(dom), pid_value);
        virDomainFree(dom);
        ret = true;
    } else {
        vshError(ctl, _("Failed to attach to pid %u"), pid_value);
    }

cleanup:
    return ret;
}

/*
 * "sysinfo" command
 */
static const vshCmdInfo info_sysinfo[] = {
    {"help", N_("print the hypervisor sysinfo")},
    {"desc",
     N_("output an XML string for the hypervisor sysinfo, if available")},
    {NULL, NULL}
};

static bool
cmdSysinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *sysinfo;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    sysinfo = virConnectGetSysinfo(ctl->conn, 0);
    if (sysinfo == NULL) {
        vshError(ctl, "%s", _("failed to get sysinfo"));
        return false;
    }

    vshPrint(ctl, "%s", sysinfo);
    VIR_FREE(sysinfo);

    return true;
}

/*
 * "hostname" command
 */
static const vshCmdInfo info_hostname[] = {
    {"help", N_("print the hypervisor hostname")},
    {"desc", ""},
    {NULL, NULL}
};

static bool
cmdHostname(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    hostname = virConnectGetHostname(ctl->conn);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        return false;
    }

    vshPrint (ctl, "%s\n", hostname);
    VIR_FREE(hostname);

    return true;
}

/*
 * "uri" command
 */
static const vshCmdInfo info_uri[] = {
    {"help", N_("print the hypervisor canonical URI")},
    {"desc", ""},
    {NULL, NULL}
};

static bool
cmdURI(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    uri = virConnectGetURI(ctl->conn);
    if (uri == NULL) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint(ctl, "%s\n", uri);
    VIR_FREE(uri);

    return true;
}

/*
 * "version" command
 */
static const vshCmdInfo info_version[] = {
    {"help", N_("show version")},
    {"desc", N_("Display the system version information.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_version[] = {
    {"daemon", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("report daemon version too")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long hvVersion;
    const char *hvType;
    unsigned long libVersion;
    unsigned long includeVersion;
    unsigned long apiVersion;
    unsigned long daemonVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    hvType = virConnectGetType(ctl->conn);
    if (hvType == NULL) {
        vshError(ctl, "%s", _("failed to get hypervisor type"));
        return false;
    }

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, _("Compiled against library: libvir %d.%d.%d\n"),
             major, minor, rel);

    ret = virGetVersion(&libVersion, hvType, &apiVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the library version"));
        return false;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, _("Using library: libvir %d.%d.%d\n"),
             major, minor, rel);

    major = apiVersion / 1000000;
    apiVersion %= 1000000;
    minor = apiVersion / 1000;
    rel = apiVersion % 1000;
    vshPrint(ctl, _("Using API: %s %d.%d.%d\n"), hvType,
             major, minor, rel);

    ret = virConnectGetVersion(ctl->conn, &hvVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the hypervisor version"));
        return false;
    }
    if (hvVersion == 0) {
        vshPrint(ctl,
                 _("Cannot extract running %s hypervisor version\n"), hvType);
    } else {
        major = hvVersion / 1000000;
        hvVersion %= 1000000;
        minor = hvVersion / 1000;
        rel = hvVersion % 1000;

        vshPrint(ctl, _("Running hypervisor: %s %d.%d.%d\n"),
                 hvType, major, minor, rel);
    }

    if (vshCommandOptBool(cmd, "daemon")) {
        ret = virConnectGetLibVersion(ctl->conn, &daemonVersion);
        if (ret < 0) {
            vshError(ctl, "%s", _("failed to get the daemon version"));
        } else {
            major = daemonVersion / 1000000;
            daemonVersion %= 1000000;
            minor = daemonVersion / 1000;
            rel = daemonVersion % 1000;
            vshPrint(ctl, _("Running against daemon: %d.%d.%d\n"),
                     major, minor, rel);
        }
    }

    return true;
}

static const vshCmdDef hostAndHypervisorCmds[] = {
    {"capabilities", cmdCapabilities, NULL, info_capabilities, 0},
    {"connect", cmdConnect, opts_connect, info_connect,
     VSH_CMD_FLAG_NOCONNECT},
    {"freecell", cmdFreecell, opts_freecell, info_freecell, 0},
    {"hostname", cmdHostname, NULL, info_hostname, 0},
    {"nodecpustats", cmdNodeCpuStats, opts_node_cpustats, info_nodecpustats, 0},
    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo, 0},
    {"nodememstats", cmdNodeMemStats, opts_node_memstats, info_nodememstats, 0},
    {"nodesuspend", cmdNodeSuspend, opts_node_suspend, info_nodesuspend, 0},
    {"qemu-attach", cmdQemuAttach, opts_qemu_attach, info_qemu_attach, 0},
    {"qemu-monitor-command", cmdQemuMonitorCommand, opts_qemu_monitor_command,
     info_qemu_monitor_command, 0},
    {"sysinfo", cmdSysinfo, NULL, info_sysinfo, 0},
    {"uri", cmdURI, NULL, info_uri, 0},
    {"version", cmdVersion, opts_version, info_version, 0},
    {NULL, NULL, NULL, NULL, 0}
};
