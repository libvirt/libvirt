/*
 * libvirt-host.c: entry points for vir{Connect,Node}Ptr APIs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
#include <sys/stat.h>

#include "datatypes.h"
#include "viralloc.h"
#include "virlog.h"
#include "virtypedparam.h"

VIR_LOG_INIT("libvirt.host");

#define VIR_FROM_THIS VIR_FROM_DOMAIN


/**
 * virConnectRef:
 * @conn: the connection to hold a reference on
 *
 * Increment the reference count on the connection. For each
 * additional call to this method, there shall be a corresponding
 * call to virConnectClose to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a connection would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure
 *
 * Since: 0.6.0
 */
int
virConnectRef(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virObjectRef(conn);
    return 0;
}


/**
 * virConnectSetIdentity:
 * @conn: pointer to the hypervisor connection
 * @params: parameters containing the identity attributes
 * @nparams: size of @params array
 * @flags: currently unused, pass 0
 *
 * Override the default identity information associated with
 * the connection. When connecting to a stateful driver over
 * a UNIX socket, the daemon will interrogate the remote end
 * of the UNIX socket to acquire the application's identity.
 * This identity is used for the fine grained access control
 * checks on API calls.
 *
 * There may be times when application is operating on behalf
 * of a variety of users, and thus the identity that the
 * application runs as is not appropriate for access control
 * checks. In this case, if the application is considered
 * trustworthy, it can supply alternative identity information.
 *
 * The driver may reject the request to change the identity
 * on a connection if the application is not trustworthy.
 *
 * Returns: 0 if the identity change was accepted, -1 on error
 *
 * Since: 5.8.0
 */
int
virConnectSetIdentity(virConnectPtr conn,
                      virTypedParameterPtr params,
                      int nparams,
                      unsigned int flags)
{
    VIR_DEBUG("conn=%p params=%p nparams=%d flags=0x%x", conn, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (conn->driver->connectSetIdentity) {
        int ret = conn->driver->connectSetIdentity(conn, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of driver features in the remote case.
 */
int
virConnectSupportsFeature(virConnectPtr conn, int feature)
{
    int ret;
    VIR_DEBUG("conn=%p, feature=%d", conn, feature);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (!conn->driver->connectSupportsFeature)
        ret = 0;
    else
        ret = conn->driver->connectSupportsFeature(conn, feature);

    if (ret < 0)
        virDispatchError(conn);

    return ret;
}


/**
 * virConnectGetType:
 * @conn: pointer to the hypervisor connection
 *
 * Get the name of the Hypervisor driver used. This is merely the driver
 * name; for example, both KVM and QEMU guests are serviced by the
 * driver for the qemu:// URI, so a return of "QEMU" does not indicate
 * whether KVM acceleration is present.  For more details about the
 * hypervisor, use virConnectGetCapabilities().
 *
 * Returns NULL in case of error, a static zero terminated string otherwise.
 *
 * Since: 0.0.3
 */
const char *
virConnectGetType(virConnectPtr conn)
{
    const char *ret;
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetType) {
        ret = conn->driver->connectGetType(conn);
        if (ret) return ret;
    }
    return conn->driver->name;
}


/**
 * virConnectGetVersion:
 * @conn: pointer to the hypervisor connection
 * @hvVer: return value for the version of the running hypervisor (OUT)
 *
 * Get the version level of the Hypervisor running. This may work only with
 * hypervisor call, i.e. with privileged access to the hypervisor, not
 * with a Read-Only connection.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 *
 * Since: 0.0.3
 */
int
virConnectGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    VIR_DEBUG("conn=%p, hvVer=%p", conn, hvVer);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(hvVer, error);

    if (conn->driver->connectGetVersion) {
        int ret = conn->driver->connectGetVersion(conn, hvVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectGetLibVersion:
 * @conn: pointer to the hypervisor connection
 * @libVer: returns the libvirt library version used on the connection (OUT)
 *
 * Provides @libVer, which is the version of libvirt used by the
 *   daemon running on the @conn host
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer have
 *      the format major * 1,000,000 + minor * 1,000 + release.
 *
 * Since: 0.7.3
 */
int
virConnectGetLibVersion(virConnectPtr conn, unsigned long *libVer)
{
    int ret = -1;
    VIR_DEBUG("conn=%p, libVir=%p", conn, libVer);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(libVer, error);

    if (conn->driver->connectGetLibVersion) {
        ret = conn->driver->connectGetLibVersion(conn, libVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    *libVer = LIBVIR_VERSION_NUMBER;
    return 0;

 error:
    virDispatchError(conn);
    return ret;
}


/**
 * virConnectGetHostname:
 * @conn: pointer to a hypervisor connection
 *
 * This returns a system hostname on which the hypervisor is
 * running (based on the result of the gethostname system call, but
 * possibly expanded to a fully-qualified domain name via getaddrinfo).
 * If we are connected to a remote system, then this returns the
 * hostname of the remote system.
 *
 * Returns the hostname which must be freed by the caller, or
 * NULL if there was an error.
 *
 * Since: 0.3.0
 */
char *
virConnectGetHostname(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetHostname) {
        char *ret = conn->driver->connectGetHostname(conn);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectGetURI:
 * @conn: pointer to a hypervisor connection
 *
 * This returns the URI (name) of the hypervisor connection.
 * Normally this is the same as or similar to the string passed
 * to the virConnectOpen/virConnectOpenReadOnly call, but
 * the driver may make the URI canonical.  If name == NULL
 * was passed to virConnectOpen, then the driver will return
 * a non-NULL URI which can be used to connect to the same
 * hypervisor later.
 *
 * Returns the URI string which must be freed by the caller, or
 * NULL if there was an error.
 *
 * Since: 0.3.0
 */
char *
virConnectGetURI(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    return virURIFormat(conn->uri);
}


/**
 * virConnectGetSysinfo:
 * @conn: pointer to a hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This returns the XML description of the sysinfo details for the
 * host on which the hypervisor is running, in the same format as the
 * <sysinfo> element of a domain XML.  This information is generally
 * available only for hypervisors running with root privileges.
 *
 * Returns the XML string which must be freed by the caller, or
 * NULL if there was an error.
 *
 * Since: 0.8.8
 */
char *
virConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=0x%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetSysinfo) {
        char *ret = conn->driver->connectGetSysinfo(conn, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectGetMaxVcpus:
 * @conn: pointer to the hypervisor connection
 * @type: value of the 'type' attribute in the <domain> element
 *
 * Provides the maximum number of virtual CPUs supported for a guest VM of a
 * specific type. The 'type' parameter here corresponds to the 'type'
 * attribute in the <domain> element of the XML. This API doesn't take emulator
 * limits into consideration, hence the returned value is not guaranteed to be
 * usable. It is recommended to use virConnectGetDomainCapabilities() and look
 * for "<vcpu max='...'>" in its output instead.
 *
 * Returns the maximum of virtual CPU or -1 in case of error.
 *
 * Since: 0.2.1
 */
int
virConnectGetMaxVcpus(virConnectPtr conn,
                      const char *type)
{
    VIR_DEBUG("conn=%p, type=%s", conn, NULLSTR(type));

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectGetMaxVcpus) {
        int ret = conn->driver->connectGetMaxVcpus(conn, type);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetInfo:
 * @conn: pointer to the hypervisor connection
 * @info: pointer to a virNodeInfo structure allocated by the user
 *
 * Extract hardware information about the node.
 *
 * Use of this API is strongly discouraged as the information provided
 * is not guaranteed to be accurate on all hardware platforms.
 *
 * The mHZ value merely reflects the speed that the first CPU in the
 * machine is currently running at. This speed may vary across CPUs
 * and changes continually as the host OS throttles.
 *
 * The nodes/sockets/cores/threads data is potentially inaccurate as
 * it assumes a symmetric installation. If one NUMA node has more
 * sockets populated that another NUMA node this information will be
 * wrong. It is also not able to report about CPU dies.
 *
 * Applications are recommended to use the virConnectGetCapabilities()
 * call instead, which provides all the information except CPU mHZ,
 * in a more accurate representation.
 *
 * Returns 0 in case of success and -1 in case of failure.
 *
 * Since: 0.1.0
 */
int
virNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    VIR_DEBUG("conn=%p, info=%p", conn, info);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(info, error);

    if (conn->driver->nodeGetInfo) {
        int ret;
        ret = conn->driver->nodeGetInfo(conn, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectGetCapabilities:
 * @conn: pointer to the hypervisor connection
 *
 * Provides capabilities of the hypervisor / driver.
 *
 * Returns NULL in case of error, or an XML string
 * defining the capabilities.
 * The client must free the returned string after use.
 *
 * Since: 0.2.1
 */
char *
virConnectGetCapabilities(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetCapabilities) {
        char *ret;
        ret = conn->driver->connectGetCapabilities(conn);
        if (!ret)
            goto error;
        VIR_DEBUG("conn=%p ret=%s", conn, ret);
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNodeGetCPUStats:
 * @conn: pointer to the hypervisor connection.
 * @cpuNum: number of node cpu. (VIR_NODE_CPU_STATS_ALL_CPUS means total cpu
 *          statistics)
 * @params: pointer to node cpu time parameter objects
 * @nparams: number of node cpu time parameter (this value should be same or
 *          less than the number of parameters supported)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function provides individual cpu statistics of the node.
 * If you want to get total cpu statistics of the node, you must specify
 * VIR_NODE_CPU_STATS_ALL_CPUS to @cpuNum.
 * The @params array will be filled with the values equal to the number of
 * parameters suggested by @nparams
 *
 * As the value of @nparams is dynamic, call the API setting @nparams to 0 and
 * @params as NULL, the API returns the number of parameters supported by the
 * HV by updating @nparams on SUCCESS. The caller should then allocate @params
 * array, i.e. (sizeof(@virNodeCPUStats) * @nparams) bytes and call
 * the API again.
 *
 * Here is a sample code snippet:
 *
 *   if (virNodeGetCPUStats(conn, cpuNum, NULL, &nparams, 0) == 0 &&
 *       nparams != 0) {
 *       if ((params = malloc(sizeof(virNodeCPUStats) * nparams)) == NULL)
 *           goto error;
 *       memset(params, 0, sizeof(virNodeCPUStats) * nparams);
 *       if (virNodeGetCPUStats(conn, cpuNum, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function doesn't require privileged access to the hypervisor.
 * This function expects the caller to allocate the @params.
 *
 * CPU time Statistics:
 *
 * VIR_NODE_CPU_STATS_KERNEL:
 *     The cumulative CPU time which spends by kernel,
 *     when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_USER:
 *     The cumulative CPU time which spends by user processes,
 *     when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_IDLE:
 *     The cumulative idle CPU time, when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_IOWAIT:
 *     The cumulative I/O wait CPU time, when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_UTILIZATION:
 *     The CPU utilization. The usage value is in percent and 100%
 *     represents all CPUs on the server.
 *
 * Returns -1 in case of error, 0 in case of success.
 *
 * Since: 0.9.3
 */
int
virNodeGetCPUStats(virConnectPtr conn,
                   int cpuNum,
                   virNodeCPUStatsPtr params,
                   int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cpuNum=%d, params=%p, nparams=%d, flags=0x%x",
              conn, cpuNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (cpuNum < 0 && cpuNum != VIR_NODE_CPU_STATS_ALL_CPUS) {
        virReportInvalidArg(cpuNum,
                            _("cpuNum in %1$s only accepts %2$d as a negative value"),
                            __FUNCTION__, VIR_NODE_CPU_STATS_ALL_CPUS);
        goto error;
    }

    if (conn->driver->nodeGetCPUStats) {
        int ret;
        ret = conn->driver->nodeGetCPUStats(conn, cpuNum, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetMemoryStats:
 * @conn: pointer to the hypervisor connection.
 * @cellNum: number of node cell. (VIR_NODE_MEMORY_STATS_ALL_CELLS means total
 *           cell statistics)
 * @params: pointer to node memory stats objects
 * @nparams: number of node memory stats (this value should be same or
 *          less than the number of stats supported)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function provides memory stats of the node.
 * If you want to get total memory statistics of the node, you must specify
 * VIR_NODE_MEMORY_STATS_ALL_CELLS to @cellNum.
 * The @params array will be filled with the values equal to the number of
 * stats suggested by @nparams
 *
 * As the value of @nparams is dynamic, call the API setting @nparams to 0 and
 * @params as NULL, the API returns the number of parameters supported by the
 * HV by updating @nparams on SUCCESS. The caller should then allocate @params
 * array, i.e. (sizeof(@virNodeMemoryStats) * @nparams) bytes and call
 * the API again.
 *
 * Here is the sample code snippet:
 *
 *   if (virNodeGetMemoryStats(conn, cellNum, NULL, &nparams, 0) == 0 &&
 *       nparams != 0) {
 *       if ((params = malloc(sizeof(virNodeMemoryStats) * nparams)) == NULL)
 *           goto error;
 *       memset(params, cellNum, 0, sizeof(virNodeMemoryStats) * nparams);
 *       if (virNodeGetMemoryStats(conn, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function doesn't require privileged access to the hypervisor.
 * This function expects the caller to allocate the @params.
 *
 * Memory Stats:
 *
 * VIR_NODE_MEMORY_STATS_TOTAL:
 *     The total memory usage.(KB)
 * VIR_NODE_MEMORY_STATS_FREE:
 *     The free memory usage.(KB)
 *     On linux, this usage includes buffers and cached.
 * VIR_NODE_MEMORY_STATS_BUFFERS:
 *     The buffers memory usage.(KB)
 * VIR_NODE_MEMORY_STATS_CACHED:
 *     The cached memory usage.(KB)
 *
 * Returns -1 in case of error, 0 in case of success.
 *
 * Since: 0.9.3
 */
int
virNodeGetMemoryStats(virConnectPtr conn,
                      int cellNum,
                      virNodeMemoryStatsPtr params,
                      int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cellNum=%d, params=%p, nparams=%d, flags=0x%x",
              conn, cellNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (cellNum < 0 && cellNum != VIR_NODE_MEMORY_STATS_ALL_CELLS) {
        virReportInvalidArg(cpuNum,
                            _("cellNum in %1$s only accepts %2$d as a negative value"),
                            __FUNCTION__, VIR_NODE_MEMORY_STATS_ALL_CELLS);
        goto error;
    }

    if (conn->driver->nodeGetMemoryStats) {
        int ret;
        ret = conn->driver->nodeGetMemoryStats(conn, cellNum, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetFreeMemory:
 * @conn: pointer to the hypervisor connection
 *
 * provides the free memory available on the Node
 * Note: most libvirt APIs provide memory sizes in kibibytes, but in this
 * function the returned value is in bytes. Divide by 1024 as necessary.
 *
 * Returns the available free memory in bytes or 0 in case of error
 *
 * Since: 0.3.3
 */
unsigned long long
virNodeGetFreeMemory(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, 0);

    if (conn->driver->nodeGetFreeMemory) {
        unsigned long long ret;
        ret = conn->driver->nodeGetFreeMemory(conn);
        if (ret == 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return 0;
}


/**
 * virNodeSuspendForDuration:
 * @conn: pointer to the hypervisor connection
 * @target: the state to which the host must be suspended to,
 *         such as: VIR_NODE_SUSPEND_TARGET_MEM (Suspend-to-RAM)
 *                  VIR_NODE_SUSPEND_TARGET_DISK (Suspend-to-Disk)
 *                  VIR_NODE_SUSPEND_TARGET_HYBRID (Hybrid-Suspend,
 *                  which is a combination of the former modes).
 * @duration: the time duration in seconds for which the host
 *            has to be suspended
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Attempt to suspend the node (host machine) for the given duration of
 * time in the specified state (Suspend-to-RAM, Suspend-to-Disk or
 * Hybrid-Suspend). Schedule the node's Real-Time-Clock interrupt to
 * resume the node after the duration is complete.
 *
 * Returns 0 on success (i.e., the node will be suspended after a short
 * delay), -1 on failure (the operation is not supported, or an attempted
 * suspend is already underway).
 *
 * Since: 0.9.8
 */
int
virNodeSuspendForDuration(virConnectPtr conn,
                          unsigned int target,
                          unsigned long long duration,
                          unsigned int flags)
{
    VIR_DEBUG("conn=%p, target=%d, duration=%lld, flags=0x%x",
              conn, target, duration, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->nodeSuspendForDuration) {
        int ret;
        ret = conn->driver->nodeSuspendForDuration(conn, target,
                                                   duration, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * virNodeGetMemoryParameters:
 * @conn: pointer to the hypervisor connection
 * @params: pointer to memory parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of memory parameters; input and output
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get all node memory parameters (parameters unsupported by OS will be
 * omitted).  On input, @nparams gives the size of the @params array;
 * on output, @nparams gives how many slots were filled with parameter
 * information, which might be less but will not exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.  See virDomainGetMemoryParameters() for an equivalent usage
 * example.
 *
 * Returns 0 in case of success, and -1 in case of failure.
 *
 * Since: 0.10.2
 */
int
virNodeGetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int *nparams,
                           unsigned int flags)
{
    int rc;

    VIR_DEBUG("conn=%p, params=%p, nparams=%p, flags=0x%x",
              conn, params, nparams, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    rc = VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                  VIR_DRV_FEATURE_TYPED_PARAM_STRING);
    if (rc < 0)
        goto error;
    if (rc)
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    if (conn->driver->nodeGetMemoryParameters) {
        int ret;
        ret = conn->driver->nodeGetMemoryParameters(conn, params,
                                                    nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * virNodeSetMemoryParameters:
 * @conn: pointer to the hypervisor connection
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned
 *           value nparams of virDomainGetSchedulerType)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Change all or a subset of the node memory tunables. The function
 * fails if not all of the tunables are supported.
 *
 * Note that it's not recommended to use this function while the
 * outside tuning program is running (such as ksmtuned under Linux),
 * as they could change the tunables in parallel, which could cause
 * conflicts.
 *
 * This function may require privileged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 0.10.2
 */
int
virNodeSetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, params=%p, nparams=%d, flags=0x%x",
              conn, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->nodeSetMemoryParameters) {
        int ret;
        ret = conn->driver->nodeSetMemoryParameters(conn, params,
                                                          nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetSecurityModel:
 * @conn: a connection object
 * @secmodel: pointer to a virSecurityModel structure
 *
 * Extract the security model of a hypervisor. The 'model' field
 * in the @secmodel argument may be initialized to the empty
 * string if the driver has not activated a security model.
 *
 * Returns 0 in case of success, -1 in case of failure
 *
 * Since: 0.6.1
 */
int
virNodeGetSecurityModel(virConnectPtr conn, virSecurityModelPtr secmodel)
{
    VIR_DEBUG("conn=%p secmodel=%p", conn, secmodel);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(secmodel, error);

    if (conn->driver->nodeGetSecurityModel) {
        int ret;
        ret = conn->driver->nodeGetSecurityModel(conn, secmodel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetCellsFreeMemory:
 * @conn: pointer to the hypervisor connection
 * @freeMems: pointer to the array of unsigned long long
 * @startCell: index of first cell to return freeMems info on.
 * @maxCells: Maximum number of cells for which freeMems information can
 *            be returned.
 *
 * This call returns the amount of free memory in one or more NUMA cells.
 * The @freeMems array must be allocated by the caller and will be filled
 * with the amount of free memory in bytes for each cell requested,
 * starting with startCell (in freeMems[0]), up to either
 * (startCell + maxCells), or the number of additional cells in the node,
 * whichever is smaller.
 *
 * Returns the number of entries filled in freeMems, or -1 in case of error.
 *
 * Since: 0.3.3
 */
int
virNodeGetCellsFreeMemory(virConnectPtr conn, unsigned long long *freeMems,
                          int startCell, int maxCells)
{
    VIR_DEBUG("conn=%p, freeMems=%p, startCell=%d, maxCells=%d",
          conn, freeMems, startCell, maxCells);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(freeMems, maxCells, error);
    virCheckPositiveArgGoto(maxCells, error);
    virCheckNonNegativeArgGoto(startCell, error);

    if (conn->driver->nodeGetCellsFreeMemory) {
        int ret;
        ret = conn->driver->nodeGetCellsFreeMemory(conn, freeMems, startCell, maxCells);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectIsEncrypted:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is encrypted
 *
 * Returns 1 if encrypted, 0 if not encrypted, -1 on error
 *
 * Since: 0.7.3
 */
int
virConnectIsEncrypted(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsEncrypted) {
        int ret;
        ret = conn->driver->connectIsEncrypted(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectIsSecure:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is secure
 *
 * A connection will be classed as secure if it is either
 * encrypted, or running over a channel which is not exposed
 * to eavesdropping (eg a UNIX domain socket, or pipe)
 *
 * Returns 1 if secure, 0 if not secure, -1 on error
 *
 * Since: 0.7.3
 */
int
virConnectIsSecure(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsSecure) {
        int ret;
        ret = conn->driver->connectIsSecure(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectCompareCPU:
 * @conn: virConnect connection
 * @xmlDesc: XML describing the CPU to compare with host CPU
 * @flags: bitwise-OR of virConnectCompareCPUFlags
 *
 * Compares the given CPU description with the host CPU.
 *
 * See virConnectCompareHypervisorCPU() if you want to consider hypervisor
 * abilities and compare the CPU to the CPU which a hypervisor is able to
 * provide on the host.
 *
 * Returns comparison result according to enum virCPUCompareResult. If
 * VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE is used and @xmlDesc CPU is
 * incompatible with host CPU, this function will return VIR_CPU_COMPARE_ERROR
 * (instead of VIR_CPU_COMPARE_INCOMPATIBLE) and the error will use the
 * VIR_ERR_CPU_INCOMPATIBLE code with a message providing more details about
 * the incompatibility.
 *
 * Since: 0.7.5
 */
int
virConnectCompareCPU(virConnectPtr conn,
                     const char *xmlDesc,
                     unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=0x%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, VIR_CPU_COMPARE_ERROR);
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->driver->connectCompareCPU) {
        int ret;

        ret = conn->driver->connectCompareCPU(conn, xmlDesc, flags);
        if (ret == VIR_CPU_COMPARE_ERROR)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return VIR_CPU_COMPARE_ERROR;
}


/**
 * virConnectCompareHypervisorCPU:
 * @conn: pointer to the hypervisor connection
 * @emulator: path to the emulator binary
 * @arch: CPU architecture
 * @machine: machine type
 * @virttype: virtualization type
 * @xmlCPU: XML describing the CPU to be compared
 * @flags: bitwise-OR of virConnectCompareCPUFlags
 *
 * Compares the given CPU description with the CPU the specified hypervisor is
 * able to provide on the host. Any of @emulator, @arch, @machine, and
 * @virttype parameters may be NULL; libvirt will choose sensible defaults
 * tailored to the host and its current configuration.
 *
 * This is different from virConnectCompareCPU() which compares the CPU
 * definition with the host CPU without considering any specific hypervisor and
 * its abilities.
 *
 * Returns comparison result according to enum virCPUCompareResult. If
 * VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE is used and @xmlCPU is
 * incompatible with the CPU the specified hypervisor is able to provide on the
 * host, this function will return VIR_CPU_COMPARE_ERROR (instead of
 * VIR_CPU_COMPARE_INCOMPATIBLE) and the error will use the
 * VIR_ERR_CPU_INCOMPATIBLE code with a message providing more details about
 * the incompatibility.
 *
 * Since: 4.4.0
 */
int
virConnectCompareHypervisorCPU(virConnectPtr conn,
                               const char *emulator,
                               const char *arch,
                               const char *machine,
                               const char *virttype,
                               const char *xmlCPU,
                               unsigned int flags)
{
    VIR_DEBUG("conn=%p, emulator=%s, arch=%s, machine=%s, "
              "virttype=%s, xmlCPU=%s, flags=0x%x",
              conn, NULLSTR(emulator), NULLSTR(arch), NULLSTR(machine),
              NULLSTR(virttype), NULLSTR(xmlCPU), flags);

    virResetLastError();

    virCheckConnectReturn(conn, VIR_CPU_COMPARE_ERROR);
    virCheckNonNullArgGoto(xmlCPU, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->connectCompareHypervisorCPU) {
        int ret;

        ret = conn->driver->connectCompareHypervisorCPU(conn, emulator, arch,
                                                        machine, virttype,
                                                        xmlCPU, flags);
        if (ret == VIR_CPU_COMPARE_ERROR)
            goto error;

        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return VIR_CPU_COMPARE_ERROR;
}


/**
 * virConnectGetCPUModelNames:
 *
 * @conn: virConnect connection
 * @arch: Architecture
 * @models: Pointer to a variable to store the NULL-terminated array of the
 *          CPU models supported for the specified architecture.  Each element
 *          and the array itself must be freed by the caller with free.  Pass
 *          NULL if only the list length is needed.
 * @flags: extra flags; not used yet, so callers should always pass 0.
 *
 * Get the list of CPU models supported by libvirt for a specific architecture.
 *
 * The returned list limits CPU models usable with libvirt (empty list means
 * there's no limit imposed by libvirt) and it does not reflect capabilities of
 * any particular hypervisor. See the XML returned by
 * virConnectGetDomainCapabilities() for a list of CPU models supported by
 * libvirt for domains created on a specific hypervisor.
 *
 * Returns -1 on error, number of elements in @models on success (0 means
 * libvirt accepts any CPU model).
 *
 * Since: 1.1.3
 */
int
virConnectGetCPUModelNames(virConnectPtr conn, const char *arch, char ***models,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, arch=%s, models=%p, flags=0x%x",
              conn, NULLSTR(arch), models, flags);
    virResetLastError();

    if (models)
        *models = NULL;

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(arch, error);

    if (conn->driver->connectGetCPUModelNames) {
        int ret;

        ret = conn->driver->connectGetCPUModelNames(conn, arch, models, flags);
        if (ret < 0)
            goto error;

        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectBaselineCPU:
 *
 * @conn: virConnect connection
 * @xmlCPUs: array of XML descriptions of host CPUs
 * @ncpus: number of CPUs in xmlCPUs
 * @flags: bitwise-OR of virConnectBaselineCPUFlags
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * host CPUs.
 *
 * See virConnectBaselineHypervisorCPU() to get a CPU which can be provided
 * by the hypervisor.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES then libvirt
 * will explicitly list all CPU features that are part of the host CPU,
 * without this flag features that are part of the CPU model will not be
 * listed.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_MIGRATABLE, the resulting
 * CPU will not include features that block migration.
 *
 * Returns XML description of the computed CPU (caller frees) or NULL on error.
 *
 * Since: 0.7.7
 */
char *
virConnectBaselineCPU(virConnectPtr conn,
                      const char **xmlCPUs,
                      unsigned int ncpus,
                      unsigned int flags)
{
    size_t i;

    VIR_DEBUG("conn=%p, xmlCPUs=%p, ncpus=%u, flags=0x%x",
              conn, xmlCPUs, ncpus, flags);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%zu]=%s", i, NULLSTR(xmlCPUs[i]));
    }

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlCPUs, error);

    if (conn->driver->connectBaselineCPU) {
        char *cpu;

        cpu = conn->driver->connectBaselineCPU(conn, xmlCPUs, ncpus, flags);
        if (!cpu)
            goto error;
        return cpu;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectBaselineHypervisorCPU:
 *
 * @conn: pointer to the hypervisor connection
 * @emulator: path to the emulator binary
 * @arch: CPU architecture
 * @machine: machine type
 * @virttype: virtualization type
 * @xmlCPUs: array of XML descriptions of CPUs
 * @ncpus: number of CPUs in xmlCPUs
 * @flags: bitwise-OR of virConnectBaselineCPUFlags
 *
 * Computes the most feature-rich CPU which is compatible with all given CPUs
 * and can be provided by the specified hypervisor. For best results the
 * host-model CPUs as advertised by virConnectGetDomainCapabilities() should be
 * passed in @xmlCPUs. Any of @emulator, @arch, @machine, and @virttype
 * parameters may be NULL; libvirt will choose sensible defaults tailored to
 * the host and its current configuration.
 *
 * This is different from virConnectBaselineCPU() which doesn't consider any
 * hypervisor abilities when computing the best CPU.
 *
 * If @ncpus == 1, the result will be the first (and only) CPU in @xmlCPUs
 * tailored to what the hypervisor can support on the current host.
 * Specifically if this single CPU definition contains no feature elements and
 * a CPU model listed as usable='no' in domain capabilities XML, the result
 * will contain a list usability blockers, i.e., a list of features that would
 * need to be disabled to for the model to be usable on this host. This list
 * may contain more features than what the hypervisor reports as blockers in
 * case the CPU model definition in libvirt differs from QEMU definition.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES then libvirt
 * will explicitly list all CPU features that are part of the computed CPU,
 * without this flag features that are part of the CPU model will not be
 * listed.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_MIGRATABLE, the resulting
 * CPU will not include features that block migration.
 *
 * Returns XML description of the computed CPU (caller frees) or NULL on error.
 *
 * Since: 4.4.0
 */
char *
virConnectBaselineHypervisorCPU(virConnectPtr conn,
                                const char *emulator,
                                const char *arch,
                                const char *machine,
                                const char *virttype,
                                const char **xmlCPUs,
                                unsigned int ncpus,
                                unsigned int flags)
{
    size_t i;

    VIR_DEBUG("conn=%p, emulator=%s, arch=%s, machine=%s, "
              "virttype=%s, xmlCPUs=%p, ncpus=%u, flags=0x%x",
              conn, NULLSTR(emulator), NULLSTR(arch), NULLSTR(machine),
              NULLSTR(virttype), xmlCPUs, ncpus, flags);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%zu]=%s", i, NULLSTR(xmlCPUs[i]));
    }

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlCPUs, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->connectBaselineHypervisorCPU) {
        char *cpu;

        cpu = conn->driver->connectBaselineHypervisorCPU(conn, emulator, arch,
                                                         machine, virttype,
                                                         xmlCPUs, ncpus, flags);
        if (!cpu)
            goto error;

        return cpu;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectSetKeepAlive:
 * @conn: pointer to a hypervisor connection
 * @interval: number of seconds of inactivity before a keepalive message is sent
 * @count: number of messages that can be sent in a row
 *
 * Start sending keepalive messages after @interval seconds of inactivity and
 * consider the connection to be broken when no response is received after
 * @count keepalive messages sent in a row.  In other words, sending count + 1
 * keepalive message results in closing the connection.  When @interval is
 * <= 0, no keepalive messages will be sent.  When @count is 0, the connection
 * will be automatically closed after @interval seconds of inactivity without
 * sending any keepalive messages.
 *
 * Note: The client has to implement and run an event loop with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl() to be able to
 * use keepalive messages.  Failure to do so may result in connections
 * being closed unexpectedly.
 *
 * Note: This API function controls only keepalive messages sent by the client.
 * If the server is configured to use keepalive you still need to run the event
 * loop to respond to them, even if you disable keepalives by this function.
 *
 * Returns -1 on error, 0 on success, 1 when remote party doesn't support
 * keepalive messages.
 *
 * Since: 0.9.8
 */
int
virConnectSetKeepAlive(virConnectPtr conn,
                       int interval,
                       unsigned int count)
{
    VIR_DEBUG("conn=%p, interval=%d, count=%u", conn, interval, count);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectSetKeepAlive) {
        int ret = conn->driver->connectSetKeepAlive(conn, interval, count);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectIsAlive:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is still alive
 *
 * A connection will be classed as alive if it is either local, or running
 * over a channel (TCP or UNIX socket) which is not closed.
 *
 * Returns 1 if alive, 0 if dead, -1 on error
 *
 * Since: 0.9.8
 */
int
virConnectIsAlive(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsAlive) {
        int ret;
        ret = conn->driver->connectIsAlive(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectRegisterCloseCallback:
 * @conn: pointer to connection object
 * @cb: callback to invoke upon close
 * @opaque: user data to pass to @cb
 * @freecb: callback to free @opaque
 *
 * Registers a callback to be invoked when the connection
 * is closed. This callback is invoked when there is any
 * condition that causes the socket connection to the
 * hypervisor to be closed.
 *
 * This function is only applicable to hypervisor drivers
 * which maintain a persistent open connection. Drivers
 * which open a new connection for every operation will
 * not invoke this.
 *
 * The @freecb must not invoke any other libvirt public
 * APIs, since it is not called from a re-entrant safe
 * context.
 *
 * Returns 0 on success, -1 on error
 *
 * Since: 0.10.0
 */
int
virConnectRegisterCloseCallback(virConnectPtr conn,
                                virConnectCloseFunc cb,
                                void *opaque,
                                virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();
    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(cb, error);

    if (conn->driver->connectRegisterCloseCallback &&
        conn->driver->connectRegisterCloseCallback(conn, cb, opaque, freecb) < 0)
        goto error;

    return 0;

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectUnregisterCloseCallback:
 * @conn: pointer to connection object
 * @cb: pointer to the current registered callback
 *
 * Unregisters the callback previously set with the
 * virConnectRegisterCloseCallback method. The callback
 * will no longer receive notifications when the connection
 * closes. If a virFreeCallback was provided at time of
 * registration, it will be invoked
 *
 * Returns 0 on success, -1 on error
 *
 * Since: 0.10.0
 */
int
virConnectUnregisterCloseCallback(virConnectPtr conn,
                                  virConnectCloseFunc cb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();
    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(cb, error);

    if (conn->driver->connectUnregisterCloseCallback &&
        conn->driver->connectUnregisterCloseCallback(conn, cb) < 0)
        goto error;

    return 0;

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetCPUMap:
 * @conn: pointer to the hypervisor connection
 * @cpumap: optional pointer to a bit map of real CPUs on the host node
 *      (in 8-bit bytes) (OUT)
 *      In case of success each bit set to 1 means that corresponding
 *      CPU is online.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 *      The bit map is allocated by virNodeGetCPUMap and needs
 *      to be released using free() by the caller.
 * @online: optional number of online CPUs in cpumap (OUT)
 *      Contains the number of online CPUs if the call was successful.
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get CPU map of host node CPUs.
 *
 * Returns number of CPUs present on the host node,
 * or -1 if there was an error.
 *
 * Since: 1.0.0
 */
int
virNodeGetCPUMap(virConnectPtr conn,
                 unsigned char **cpumap,
                 unsigned int *online,
                 unsigned int flags)
{
    VIR_DEBUG("conn=%p, cpumap=%p, online=%p, flags=0x%x",
              conn, cpumap, online, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->nodeGetCPUMap) {
        int ret = conn->driver->nodeGetCPUMap(conn, cpumap, online, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetFreePages:
 * @conn: pointer to the hypervisor connection
 * @npages: number of items in the @pages array
 * @pages: page sizes to query
 * @startCell: index of first cell to return free pages info on.
 * @cellCount: maximum number of cells for which free pages
 *             information can be returned.
 * @counts: returned counts of free pages
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This calls queries the host system on free pages of
 * specified size. For the input, @pages is expected to be
 * filled with pages that caller is interested in (the size
 * unit is kibibytes, so e.g. pass 2048 for 2MB), then @startcell
 * refers to the first NUMA node that info should be collected
 * from, and @cellcount tells how many consecutive nodes should
 * be queried. On the function output, @counts is filled with
 * desired information, where items are grouped by NUMA node.
 * So from @counts[0] till @counts[@npages - 1] you'll find count
 * for the first node (@startcell), then from @counts[@npages]
 * till @count[2 * @npages - 1] you'll find info for the
 * (@startcell + 1) node, and so on. It's callers responsibility
 * to allocate the @counts array.
 *
 * Example how to use this API:
 *
 *   unsigned int pages[] = { 4, 2048, 1048576}
 *   unsigned int npages = G_N_ELEMENTS(pages);
 *   int startcell = 0;
 *   unsigned int cellcount = 2;
 *
 *   unsigned long long counts = malloc(sizeof(long long) * npages * cellcount);
 *
 *   virNodeGetFreePages(conn, pages, npages,
 *                       startcell, cellcount, counts, 0);
 *
 *   for (i = 0 ; i < cellcount ; i++) {
 *       fprintf(stdout, "Cell %d\n", startcell + i);
 *       for (j = 0 ; j < npages ; j++) {
 *          fprintf(stdout, "  Page size=%d count=%d bytes=%llu\n",
 *                  pages[j], counts[(i * npages) +  j],
 *                  pages[j] * counts[(i * npages) +  j]);
 *       }
 *   }
 *
 *   This little code snippet will produce something like this:
 * Cell 0
 *    Page size=4096 count=300 bytes=1228800
 *    Page size=2097152 count=0 bytes=0
 *    Page size=1073741824 count=1 bytes=1073741824
 * Cell 1
 *    Page size=4096 count=0 bytes=0
 *    Page size=2097152 count=20 bytes=41943040
 *    Page size=1073741824 count=0 bytes=0
 *
 * Returns: the number of entries filled in @counts or -1 in case of error.
 *
 * Since: 1.2.6
 */
int
virNodeGetFreePages(virConnectPtr conn,
                    unsigned int npages,
                    unsigned int *pages,
                    int startCell,
                    unsigned int cellCount,
                    unsigned long long *counts,
                    unsigned int flags)
{
    VIR_DEBUG("conn=%p, npages=%u, pages=%p, startCell=%u, "
              "cellCount=%u, counts=%p, flags=0x%x",
              conn, npages, pages, startCell, cellCount, counts, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonZeroArgGoto(npages, error);
    virCheckNonNullArgGoto(pages, error);
    virCheckNonZeroArgGoto(cellCount, error);
    virCheckNonNullArgGoto(counts, error);

    if (conn->driver->nodeGetFreePages) {
        int ret;
        ret = conn->driver->nodeGetFreePages(conn, npages, pages, startCell,
                                             cellCount, counts, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeAllocPages:
 * @conn: pointer to the hypervisor connection
 * @npages: number of items in the @pageSizes and
 *          @pageCounts arrays
 * @pageSizes: which huge page sizes to allocate
 * @pageCounts: how many pages should be allocated
 * @startCell: index of first cell to allocate pages on
 * @cellCount: number of consecutive cells to allocate pages on
 * @flags: extra flags; binary-OR of virNodeAllocPagesFlags
 *
 * Sometimes, when trying to start a new domain, it may be
 * necessary to reserve some huge pages in the system pool which
 * can be then allocated by the domain. This API serves that
 * purpose. On its input, @pageSizes and @pageCounts are arrays
 * of the same cardinality of @npages. The @pageSizes contains
 * page sizes which are to be allocated in the system (the size
 * unit is kibibytes), and @pageCounts then contains the number
 * of pages to reserve.  If @flags is 0
 * (VIR_NODE_ALLOC_PAGES_ADD), each pool corresponding to
 * @pageSizes grows by the number of pages specified in the
 * corresponding @pageCounts.  If @flags contains
 * VIR_NODE_ALLOC_PAGES_SET, each pool mentioned is resized to
 * the given number of pages.  The pages pool can be allocated
 * over several NUMA nodes at once, just point at @startCell and
 * tell how many subsequent NUMA nodes should be taken in. As a
 * special case, if @startCell is equal to negative one, then
 * kernel is instructed to allocate the pages over all NUMA nodes
 * proportionally.
 *
 * Returns: the number of nodes successfully adjusted or -1 in
 * case of an error.
 *
 * Since: 1.2.9
 */
int
virNodeAllocPages(virConnectPtr conn,
                  unsigned int npages,
                  unsigned int *pageSizes,
                  unsigned long long *pageCounts,
                  int startCell,
                  unsigned int cellCount,
                  unsigned int flags)
{
    VIR_DEBUG("conn=%p npages=%u pageSizes=%p pageCounts=%p "
              "startCell=%d cellCount=%u flags=0x%x",
              conn, npages, pageSizes, pageCounts, startCell,
              cellCount, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(npages, error);
    virCheckNonNullArgGoto(pageSizes, error);
    virCheckNonNullArgGoto(pageCounts, error);
    virCheckNonZeroArgGoto(cellCount, error);

    if (conn->driver->nodeAllocPages) {
        int ret;
        ret = conn->driver->nodeAllocPages(conn, npages, pageSizes,
                                           pageCounts, startCell,
                                           cellCount, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/*
 * virNodeGetSEVInfo:
 * @conn: pointer to the hypervisor connection
 * @params: where to store  SEV information
 * @nparams: pointer to number of SEV parameters returned in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * If hypervisor supports AMD's SEV feature, then @params will contain various
 * platform specific information like PDH and certificate chain. Caller is
 * responsible for freeing @params.
 *
 * Returns 0 in case of success, and -1 in case of failure.
 *
 * Since: 4.5.0
 */
int
virNodeGetSEVInfo(virConnectPtr conn,
                  virTypedParameterPtr *params,
                  int *nparams,
                  unsigned int flags)
{
    int rc;

    VIR_DEBUG("conn=%p, params=%p, nparams=%p, flags=0x%x",
              conn, params, nparams, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    virCheckReadOnlyGoto(conn->flags, error);

    rc = VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                  VIR_DRV_FEATURE_TYPED_PARAM_STRING);
    if (rc < 0)
        goto error;
    if (rc)
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    if (conn->driver->nodeGetSEVInfo) {
        int ret;
        ret = conn->driver->nodeGetSEVInfo(conn, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}
