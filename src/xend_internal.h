/*
 * libxend/xend.h -- Xend library
 *
 * Copyright (C) 2005
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
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

#include "libvirt.h"

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
struct xend_device_vbd
{
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
struct xend_device_ioport
{
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
struct xend_device_vif
{
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

struct xend_domain_live
{
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
struct xend_domain
{
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

enum xend_node_system
{
	XEND_SYSTEM_LINUX = 1,
};

struct xend_node
{
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
 * \brief Setup the connection to the local Xend instance
 * \return 0 in case of success, -1 in case of error
 *
 * This method creates a new Xend instance preferrably trying
 * to connect with the domain socket but if necessary using
 * TCP (only on localhost though).
 *
 * This function may not fail if Xend is not running.
 *
 * Make sure to call xend_cleanup().
 */
int xend_setup(virConnectPtr conn);

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
 * Make sure to call xend_cleanup().
 */
int xend_setup_tcp(virConnectPtr xend, const char *host, int port);

/**
 * \brief Setup the connection to xend instance via a Unix domain socket
 * \param path The path to the domain socket
 * \return 0 in case of success, -1 in case of error
 * 
 * This method creates a new xend instance via a Unix domain socket.
 *
 * This function may not fail if Xend is not running.
 *
 * Make sure to call xend_cleanup().
 */
int xend_setup_unix(virConnectPtr xend, const char *path);

/**
 * \brief Delete a previously allocated Xend instance
 * \param xend The xend instance
 *
 * This method should be called when a connection to xend instance
 * initialized with xend_setup[_{tcp, unix}] is no longer needed
 * to free the associated resources.
 */
void xend_cleanup(virConnectPtr xend);

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
 * \brief Pause a domain
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will make sure that Xen does not schedule the domain
 * anymore until after xend_unpause() has been called.
 */
int xend_pause(virConnectPtr xend, const char *name);

/**
 * \brief Unpause a domain
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method will allow a paused domain (the result of xen_pause())
 * to be scheduled in the future.
 */
int xend_unpause(virConnectPtr xend, const char *name);

/**
 * \brief Unpause a domain
 * \param xend A xend instance
 * \param oldname The domain's name
 * \param name The new name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method allows a domain to have its name changed after creation.
 */
int xend_rename(virConnectPtr xend, const char *oldname, const char *name);

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
 * \brief Request a domain to reboot
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method *requests* that a domain reboot itself.  This is only
 * a request and the domain may ignore it.  It will return immediately
 * after queuing the request.
 */
int xend_reboot(virConnectPtr xend, const char *name);

/**
 * \brief Request a domain to shutdown
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method *requests* that a domain shutdown itself.  This is only
 * a request and the domain may ignore it.  It will return immediately
 * after queuing the request.
 */
int xend_shutdown(virConnectPtr xend, const char *name);

/**
 * \brief Destroy a domain
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method will immediately destroy a domain.  If you call this
 * function while a domain is running, you risk corrupting its devices.
 * After calling this function, the domain's status will change to
 * dying and will go away completely once all of the resources have been
 * unmapped (usually from the backend devices).
 */
int xend_destroy(virConnectPtr xend, const char *name);

/**
 * \brief Save a domain to the disk
 * \param xend A xend instance
 * \param name The domain's name
 * \param filename The filename to save to
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method will suspend a domain and save its memory contents to
 * a file on disk.  Use xend_restore() to restore a domain after
 * saving.
 */
int xend_save(virConnectPtr xend, const char *name, const char *filename);

/**
 * \brief Restore a domain from the disk
 * \param xend A xend instance
 * \param filename The filename to restore from
 * \return 0 for success; -1 (with errno) on error
 * 
 * This method will restore a domain saved to disk by xend_save().
 */
int xend_restore(virConnectPtr xend, const char *filename);

/**
 * \brief Obtain a list of currently running domains
 * \param xend A xend instance
 * \return a NULL terminated array of names; NULL (with errno) on error
 * 
 * This method will return an array of names of currently running
 * domains.  The memory should be released will a call to free().
 */
char **xend_get_domains(virConnectPtr xend);

/**
 * \brief Create a new domain
 * \param xend A xend instance
 * \param info A struct xen_domain instance describing the domain
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will create a domain based the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xend_unpause() to begin execution.
 */
int xend_create(virConnectPtr xend, const struct xend_domain *info);

/**
 * \brief Create a new domain
 * \param xend A xend instance
 * \param sexpr An S-Expr defining the domain
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will create a domain based the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xend_unpause() to begin execution.
 */
int xend_create_sexpr(virConnectPtr xend, const char *sexpr);

/**
 * \brief Set the maximum memory for a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \param value The maximum memory in bytes
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will set the maximum amount of memory that can be allocated to
 * a domain.  Please note that a domain is able to allocate up to this amount
 * on its own (although under normal circumstances, memory allocation for a
 * domain is only done through xend_set_memory()).
 */
int xend_set_max_memory(virConnectPtr xend, const char *name, uint64_t value);

/**
 * \brief Set the memory allocation for a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \param value The desired allocation in bytes
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will set a target memory allocation for a given domain and
 * request that the guest meet this target.  The guest may or may not actually
 * achieve this target.  When this function returns, it does not signify that
 * the domain has actually reached that target.
 *
 * Memory for a domain can only be allocated up to the maximum memory setting.
 * There is no safe guard for allocations that are too small so be careful
 * when using this function to reduce a domain's memory usage.
 */
int xend_set_memory(virConnectPtr xend, const char *name, uint64_t value);

/**
 * \brief Create a virtual block device
 * \param xend A xend instance
 * \param name The name of the domain
 * \param vbd A virtual block device description
 * \return 0 on success; -1 (with errno) on error
 *
 * This method creates and attachs a block device to a domain.  A successful
 * return value does not indicate that the device successfully attached,
 * rather, one should use xend_wait_for_devices() to block until the device
 * has been successfully attached.
 */
int xend_vbd_create(virConnectPtr xend,
		    const char *name,
		    const struct xend_device_vbd *vbd);

/**
 * \brief Destroy a virtual block device
 * \param xend A xend instance
 * \param name The name of the domain
 * \param vbd A virtual block device description
 * \return 0 on success; -1 (with errno) on error
 *
 * This method detachs a block device from a given domain.  A successful return
 * value does not indicate that the device successfully detached, rather, one
 * should use xend_wait_for_devices() to block until the device has been
 * successfully detached.
 */
int xend_vbd_destroy(virConnectPtr xend,
		     const char *name,
		     const struct xend_device_vbd *vbd);

/**
 * \brief Create a virtual network device
 * \param xend A xend instance
 * \param name The name of the domain
 * \param vif A virtual network device description
 * \return 0 on success; -1 (with errno) on error
 *
 * This method creates and attachs a network device to a domain.  A successful
 * return value does not indicate that the device successfully attached,
 * rather, one should use xend_wait_for_devices() to network until the device
 * has been successfully attached.
 */
int xend_vif_create(virConnectPtr xend,
		    const char *name,
		    const struct xend_device_vif *vif);

/**
 * \brief Destroy a virtual network device
 * \param xend A xend instance
 * \param name The name of the domain
 * \param vif A virtual network device description
 * \return 0 on success; -1 (with errno) on error
 *
 * This method detachs a network device from a given domain.  A successful
 * return value does not indicate that the device successfully detached,
 * rather, one should use xend_wait_for_devices() to network until the device
 * has been successfully detached.
 */
int xend_vif_destroy(virConnectPtr xend,
		     const char *name,
		     const struct xend_device_vif *vif);

/**
 * \brief Lookup information about a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \return domain info on success; NULL (with errno) on error
 *
 * This method looks up information about a domain and returns
 * it in the form of a struct xend_domain.  This should be
 * free()'d when no longer needed.
 */
struct xend_domain *xend_get_domain(virConnectPtr xend,
				    const char *name);

/**
 * \brief Lookup the id of a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \param uuid pointer to store a copy of the uuid
 * \return the id number on success; -1 (with errno) on error
 *
 * This method looks up the ids of a domain
 */
int xend_get_domain_ids(virConnectPtr xend,
		        const char *name,
			unsigned char *uuid);

/**
 * \brief Get status informations for a domain
 * \param domain A xend domain
 * \param info An information block provided by the user
 * \return 0 in case of success, -1 in case of error
 *
 * This method looks up information about a domain and update the
 * information block provided.
 */
int xend_get_domain_info(virDomainPtr domain,
			 virDomainInfoPtr info);

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
int xend_dmesg(virConnectPtr xend,
	       char *buffer,
	       size_t n_buffer);

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
int xend_log(virConnectPtr xend,
	     char *buffer,
	     size_t n_buffer);

/**
 * \brief Provide an XML description of the domain.
 * \param domain a xend domain object
 * \return a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 *
 * Provide an XML description of the domain.
 */
char *xend_get_domain_xml(virDomainPtr domain);
#ifdef __cplusplus
}
#endif

#endif
