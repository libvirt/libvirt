/*
 * libxend/xend.h -- Xend library
 *
 * Copyright (C) 2005,2006
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
 *	Daniel Veillard <veillard@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _LIBXEND_XEND_H_
#define _LIBXEND_XEND_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include "libvirt/libvirt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
   Use the default setting as determined by Xend.
*/
#define XEND_DEFAULT 0

/**
   This structure represents a virtual block device.
*/
    struct xend_device_vbd {

        /**
	   The domain ID of the backend.

	   Required.
	*/
        int backend;

        /**
	   A URI representing the device.  This is typically in the form
	   file:/path/to/image or phy:/dev/device

	   Required.
	*/
        const char *uname;

        /**
	   The name (or number) of the device to expose to the frontend.

	   Required.
	*/
        const char *dev;

        /**
	   A flag specifying the permissions to expose the device with.

	   Required.
	*/
        virDeviceMode mode;
    };

/**
   This structure represents a range of PIO to enable for a guest.
*/
    struct xend_device_ioport {

        /**
	   The beginning address of an ioport range to enable.

	   Required.
	*/
        uint16_t from;

        /**
	   The ending address of an ioport range to enable.

	   Required.
	*/
        uint16_t to;
    };

/**
   This structure represents a virtual network interface configuration.
*/
    struct xend_device_vif {

        /**
	   A string representing the domain that will serve as the backend for
	   this device.

	   Required.
	*/
        int backend;

        /**
	   The name of the bridge device to pass to the network script.

	   Optional.
	*/
        const char *bridge;

        /**
	   The ip address to configure the virtal network device with.

	   Optional.
	*/
        const char *ip;

        /**
	   The mac address to use for the virtual network device.

	   Required.
	*/
        uint8_t mac[6];

        /**
	   The path to the network script that is to be used for initializing
	   the network device.

	   Optional.
	*/
        const char *script;

        /**
	   The name of the vif.  The primary use for this is to allow the user
	   to operate on vifs by name.

	   Optional.
	*/
        const char *vifname;
    };

    struct xend_domain_live {

        /**
	   true is domain is currently scheduled.
	*/
        bool running;

        /**
	   true is domain has crashed.
	*/
        bool crashed;

        /**
	   true if domain has been shutdown.
	*/
        bool poweroff;

        /**
	   true if domain has requested a reboot.
	*/
        bool reboot;

        /**
	   true if domain has requested a suspend.
	*/
        bool suspend;

        /**
	   true if domain is blocked on IO
	*/
        bool blocked;

        /**
	   true if domain has been destroyed but resources are not
	   fully deallocated.
	*/
        bool dying;

        /**
	   true if domain is paused.
	*/
        bool paused;

        /**
	   the amount of time the domain has been running (in seconds)
	*/
        double cpu_time;

        /**
	   the wall clock time since the domain was created (in seconds)
	*/
        double up_time;

        /**
	   the time (in seconds since epoch) the domain was created
	*/
        double start_time;

        /**
	   the number of enabled VCPUs
	*/
        int online_vcpus;

        /**
	   the total number of available VCPUs
	*/
        int vcpu_avail;

        /**
	   the domain id number
	*/
        int id;
    };

/**
   This structure represents the configuration of a domain.  It's primary
   purpose (currently) is for domain creation.
*/
    struct xend_domain {

        /**
	   The name of the domain.

	   Required.
	*/
        const char *name;

        /**
	   The amount of memory to assign to the domain before creation.

	   Required.
	*/
        uint64_t memory;

        /**
	   The maximum amount of memory that can be given to the domain
	   while it's running.  Please note that a domain can increase its
	   memory on its own while running up to this value.

	   Required.
	*/
        uint64_t max_memory;

        /**
	   The uuid to use to identify the domain.  This is compatible with
	   libuuid's uuid_t and should be able to be used interchangably.

	   Optional.
	*/
        unsigned char *uuid;

        /**
	   The ssidref to assign to the domain.

	   Optional.
	*/
        int ssidref;

        /**
	   The action to perform when the domain powers off.

	   Optional.
	*/
        virDomainRestart on_poweroff;

        /**
	   The action to perform when the domain reboots.

	   Optional.
	*/
        virDomainRestart on_reboot;

        /**
	   The action to perform when the domain crashes.

	   Optional.
	*/
        virDomainRestart on_crash;

        /**
	   The number of VCPUs to assign to the domain.

	   Required.
	*/
        int vcpus;

        /* FIXME cpus */

        virDomainKernel image;

        /**
	   The number of VBDs pointed to be vbds.

	   Optional.
	*/
        size_t n_vbds;
        struct xend_device_vbd *vbds;

        /**
	   The number of IO port ranges pointed to by ioports.

	   Optional.
	*/
        size_t n_ioports;
        struct xend_device_ioport *ioports;

        /**
	   The number of VIFs pointed to be vifs.

	   Optional.
	*/
        size_t n_vifs;
        struct xend_device_vif *vifs;

        /**
	   A pointer to run-time information about the domain.

	   Only set by xen_get_domain().
	*/
        struct xend_domain_live *live;
    };

    enum xend_node_system {
        XEND_SYSTEM_LINUX = 1,
    };

    struct xend_node {

        /**
	   An enumeration value specifying the host system.
	*/
        enum xend_node_system system;

        /**
	   The DNS host name.
	*/
        const char *host;

        /**
	   The dom0 kernel release string.
	*/
        const char *release;

        /**
	   The result of uname -v.
	*/
        const char *version;

        /**
	   The machine type.
	*/
        const char *machine;

        /**
	   The number of physical cpus.
	*/
        int nr_cpus;

        /**
	   The number of NUMA nodes.
	*/
        int nr_nodes;

        /**
	   The number of sockets per NUMA node.
	*/
        int sockets_per_node;

        /**
	   The number of cores per NUMA socket.
	*/
        int cores_per_socket;

        /**
	   The number of hyperthreads per core.
	*/
        int threads_per_core;

        /**
	   The clock rating (in megahertz) of each core.
	*/
        int cpu_mhz;

        /**
	   I honestly don't know what this is.
	*/
        const char *hw_caps;

        /**
	   The total memory (in bytes).
	*/
        uint64_t total_memory;

        /**
	   The free memory (in bytes).
	*/
        uint64_t free_memory;

        /**
	   The Xen major version number.
	*/
        int xen_major;

        /**
	   The Xen minor version number.
	*/
        int xen_minor;

        /**
	   The Xen extra version number.
	*/
        int xen_extra;

        /**
	   A string descirbing the Xen platform.
	*/
        const char *xen_caps;

        /**
	   Dunno.
	*/
        const char *platform_params;

        /**
	   The build changeset.
	*/
        const char *xen_changeset;

        /**
	   The compiler version.
	*/
        const char *cc_compiler;

        /**
	   The user that compiled this binary.
	*/
        const char *cc_compile_by;

        /**
	   The system this binary was built on.
	*/
        const char *cc_compile_domain;

        /**
	   The date that this binary was built on.
	*/
        const char *cc_compile_date;
    };

/**
 * \brief Setup the connection to a xend instance via TCP
 * \param host The host name to connect to
 * \param port The port number to connect to
 * \return 0 in case of success, -1 in case of error
 * 
 * This method creates a new Xend instance via TCP.
 *
 * This function may not fail if Xend is not running.
 *
 * Make sure to call xenDaemonClose().
 */
int xenDaemonOpen_tcp(virConnectPtr xend, const char *host, int port);

/**
 * \brief Setup the connection to xend instance via a Unix domain socket
 * \param path The path to the domain socket
 * \return 0 in case of success, -1 in case of error
 * 
 * This method creates a new xend instance via a Unix domain socket.
 *
 * This function may not fail if Xend is not running.
 *
 * Make sure to call xenDaemonClose().
 */
int xenDaemonOpen_unix(virConnectPtr xend, const char *path);


/**
 * \brief Blocks until a domain's devices are initialized
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 * 
 * xen_create() returns after a domain has been allocated including
 * its memory.  This does not guarentee, though, that the devices
 * have come up properly.  For instance, if you create a VBD with an
 * invalid filename, the error won't occur until after this function
 * returns.
 */
    int xend_wait_for_devices(virConnectPtr xend, const char *name);

/**
 * \brief Rename a domain
 * \param xend A xend instance
 * \param oldname The domain's name
 * \param name The new name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method allows a domain to have its name changed after creation.
 */
    int xend_rename(virConnectPtr xend, const char *oldname,
                    const char *name);

/**
 * \brief Sends a SYSRQ to a domain
 * \param xend A xend instance
 * \param name The domain's name
 * \param key The key that was held during the SYSRQ
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method simulates the pressing of a SYSRQ sequence.
 */
    int xend_sysrq(virConnectPtr xend, const char *name, const char *key);

/**
 * \brief Create a new domain
 * \param xend A xend instance
 * \param sexpr An S-Expr defining the domain
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will create a domain based the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xenDaemonResumeDomain() to begin execution.
 */
    int xenDaemonDomainCreateLinux(virConnectPtr xend, const char *sexpr);

/**
 * \brief Lookup the id of a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \param uuid pointer to store a copy of the uuid
 * \return the id number on success; -1 (with errno) on error
 *
 * This method looks up the ids of a domain
 */
int xenDaemonDomainLookupByName_ids(virConnectPtr xend,
                            const char *name, unsigned char *uuid);


/**
 * \brief Lookup the name of a domain
 * \param xend A xend instance
 * \param id The id of the domain
 * \param name pointer to store a copy of the name
 * \param uuid pointer to store a copy of the uuid
 *
 * This method looks up the name/uuid of a domain
 */
int xenDaemonDomainLookupByID(virConnectPtr xend,
			      int id,
			      char **name, unsigned char *uuid);


char *xenDaemonDomainDumpXMLByID(virConnectPtr xend,
				 int domid);

/**
 * \brief Lookup information about the host machine
 * \param xend A xend instance
 * \return node info on success; NULL (with errno) on error
 *
 * This method returns information about the physical host
 * machine running Xen.
 */
    struct xend_node *xend_get_node(virConnectPtr xend);

/**
 * \brief Shutdown physical host machine
 * \param xend A xend instance
 * \return 0 on success; -1 (with errno) on error
 *
 * This method shuts down the physical machine running Xen.
 */
    int xend_node_shutdown(virConnectPtr xend);

/**
 * \brief Restarts physical host machine
 * \param xend A xend instance
 * \return 0 on success; -1 (with errno) on error
 *
 * This method restarts the physical machine running Xen.
 */
    int xend_node_restart(virConnectPtr xend);

/**
 * \brief Return hypervisor debugging messages
 * \param xend A xend instance
 * \param buffer A buffer to hold the messages
 * \param n_buffer Size of buffer (including null terminator)
 * \return 0 on success; -1 (with errno) on error
 *
 * This function will place the debugging messages from the
 * hypervisor into a buffer with a null terminator.
 */
    int xend_dmesg(virConnectPtr xend, char *buffer, size_t n_buffer);

/**
 * \brief Clear the hypervisor debugging messages
 * \param xend A xend instance
 * \return 0 on success; -1 (with errno) on error
 *
 * This function will clear the debugging message ring queue
 * in the hypervisor.
 */
    int xend_dmesg_clear(virConnectPtr xend);

/**
 * \brief Obtain the Xend log messages
 * \param xend A xend instance
 * \param buffer The buffer to hold the messages
 * \param n_buffer Size of buffer (including null terminator)
 * \return 0 on success; -1 (with errno) on error
 *
 * This function will place the Xend debugging messages into
 * a buffer with a null terminator.
 */
    int xend_log(virConnectPtr xend, char *buffer, size_t n_buffer);

  char *xend_parse_domain_sexp(virConnectPtr conn,  char *root, int xendConfigVersion);

/* refactored ones */
void xenDaemonRegister(void);
int xenDaemonOpen(virConnectPtr conn, const char *name, int flags);
int xenDaemonClose(virConnectPtr conn);
int xenDaemonGetVersion(virConnectPtr conn, unsigned long *hvVer);
int xenDaemonNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);
int xenDaemonDomainSuspend(virDomainPtr domain);
int xenDaemonDomainResume(virDomainPtr domain);
int xenDaemonDomainShutdown(virDomainPtr domain);
int xenDaemonDomainReboot(virDomainPtr domain, unsigned int flags);
int xenDaemonDomainDestroy(virDomainPtr domain);
int xenDaemonDomainSave(virDomainPtr domain, const char *filename);
int xenDaemonDomainRestore(virConnectPtr conn, const char *filename);
int xenDaemonDomainSetMemory(virDomainPtr domain, unsigned long memory);
int xenDaemonDomainSetMaxMemory(virDomainPtr domain, unsigned long memory);
int xenDaemonDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
char *xenDaemonDomainDumpXML(virDomainPtr domain, int flags);
virDomainPtr xenDaemonDomainLookupByName(virConnectPtr conn, const char *domname);
unsigned long xenDaemonDomainGetMaxMemory(virDomainPtr domain);
char **xenDaemonListDomainsOld(virConnectPtr xend);

int	xenDaemonDomainSetVcpus		(virDomainPtr domain,
					 unsigned int vcpus);
int	xenDaemonDomainPinVcpu		(virDomainPtr domain,
					 unsigned int vcpu,
					 unsigned char *cpumap,
					 int maplen);
int	xenDaemonDomainGetVcpus		(virDomainPtr domain,
					 virVcpuInfoPtr info,
					 int maxinfo,
					 unsigned char *cpumaps,
					 int maplen);

#ifdef __cplusplus
}
#endif
#endif
