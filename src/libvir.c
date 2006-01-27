/*
 * libvir.c: Main interfaces for the libvir library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xs.h>
#include "internal.h"
#include "xen_internal.h"
#include "xend_internal.h"
#include "hash.h"


/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to garantee coherent pointer state ?
 * - error reporting layer
 * - memory wrappers for malloc/free ?
 */

/**
 * virGetVersion:
 * @libVer: return value for the library version (OUT)
 * @type: hypervisor type
 * @typeVer: return value for the version of the hypervisor (OUT)
 *
 * Provides two information back, @libVer is the version of the library
 * while @typeVer will be the version of the hypervisor type @type against
 * which the library was compiled. If @type is NULL, "Xen" is assumed, if
 * @type is unknown or not availble, an error code will be returned and 
 * @typeVer will be 0.
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer and
 *       @typeVer have the format major * 1,000,000 + minor * 1,000 + release.
 */
int
virGetVersion(unsigned long *libVer, const char *type, unsigned long *typeVer) {
    if (libVer == NULL)
        return(-1);
    *libVer = LIBVIR_VERSION_NUMBER;

    if (typeVer != NULL) {
	if ((type == NULL) || (!strcasecmp(type, "Xen"))) {
	    if ((DOM0_INTERFACE_VERSION & 0xFFFF0000) == (0xAAAA0000)) {
	        /* one time glitch hopefully ! */
                *typeVer = 2 * 1000000 +
		           ((DOM0_INTERFACE_VERSION >> 8) & 0xFF) * 1000 +
			   (DOM0_INTERFACE_VERSION & 0xFF);
	    } else {
		*typeVer = (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
			   ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
			   (DOM0_INTERFACE_VERSION & 0xFFFF);
	    }
	} else {
	    *typeVer = 0;
	    return(-1);
	}
    }
    return(0);
}

/**
 * virConnectOpen:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a connection to the 
 * Hypervisor and xen store
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpen(const char *name) {
    virConnectPtr ret = NULL;
    int handle = -1;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    handle = xenHypervisorOpen();
    if (handle == -1)
        goto failed;
    xshandle = xs_daemon_open();
    if (xshandle == NULL)
        goto failed;

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = VIR_CONNECT_MAGIC;
    ret->handle = handle;
    ret->xshandle = xshandle;
    if (xend_setup(ret) < 0)
        goto failed;
    ret->domains = virHashCreate(20);
    ret->flags = 0;
    if (ret->domains == NULL)
        goto failed;

    return(ret);
failed:
    if (handle >= 0)
        xenHypervisorClose(handle);
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    if (ret != NULL)
        free(ret);
    return(NULL);
}

/**
 * virConnectOpenReadOnly:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a restricted connection to the 
 * libbrary functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpenReadOnly(const char *name) {
    int method = 0;
    int handle;
    virConnectPtr ret = NULL;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    handle = xenHypervisorOpen();
    if (handle >= 0)
        method++;
    else
        handle = -1;

    xshandle = xs_daemon_open_readonly();
    if (xshandle != NULL)
        method++;

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = VIR_CONNECT_MAGIC;
    ret->handle = handle;
    ret->xshandle = xshandle;
    if (xend_setup(ret) == 0)
        method++;
    ret->domains = virHashCreate(20);
    ret->flags = VIR_CONNECT_RO;
    if ((ret->domains == NULL) || (method == 0))
        goto failed;

    return(ret);
failed:
    if (handle >= 0)
        xenHypervisorClose(handle);
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    if (ret != NULL) {
        if (ret->domains != NULL)
	    virHashFree(ret->domains, NULL);
        free(ret);
    }
    return(NULL);
}

/**
 * virConnectCheckStoreID:
 * @conn: pointer to the hypervisor connection
 * @id: the id number as returned from Xenstore
 *
 * the xenstore sometimes list non-running domains, double check
 * from the hypervisor if we have direct access
 *
 * Returns -1 if the check failed, 0 if successful or not possible to check
 */
static int
virConnectCheckStoreID(virConnectPtr conn, int id) {
    if (conn->handle >= 0) {
	dom0_getdomaininfo_t dominfo;
	int tmp;

	dominfo.domain = id;
	tmp = xenHypervisorGetDomainInfo(conn->handle, id, &dominfo);
	if (tmp < 0)
	    return(-1);
    }
    return(0);
}

/**
 * virDomainFreeName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virDomainFreeName(virDomainPtr domain, const char *name ATTRIBUTE_UNUSED) {
    return(virDomainFree(domain));
}

/**
 * virConnectClose:
 * @conn: pointer to the hypervisor connection
 *
 * This function closes the connection to the Hypervisor. This should
 * not be called if further interaction with the Hypervisor are needed
 * especially if there is running domain which need further monitoring by
 * the application.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
virConnectClose(virConnectPtr conn) {
    xend_cleanup(conn);
    if (!VIR_IS_CONNECT(conn))
        return(-1);
    virHashFree(conn->domains, (virHashDeallocator) virDomainFreeName);
    conn->magic = -1;
    if (conn->xshandle != NULL)
	xs_daemon_close(conn->xshandle);
    conn->xshandle = NULL;
    if (conn->handle != -1)
	xenHypervisorClose(conn->handle);
    conn->handle = -1;
    free(conn);
    return(0);
}

/**
 * virConnectGetType:
 * @conn: pointer to the hypervisor connection
 *
 * Get the name of the Hypervisor software used.
 *
 * Returns NULL in case of error, a static zero terminated string otherwise.
 */
const char *
virConnectGetType(virConnectPtr conn) {
    if (!VIR_IS_CONNECT(conn))
        return(NULL);
    return("Xen");
}

/**
 * virConnectGetVersion:
 * @conn: pointer to the hypervisor connection
 * @hvVer: return value for the version of the running hypervisor (OUT)
 *
 * Get the version level of the Hypervisor running. This may work only with 
 * hypervisor call, i.e. with priviledged access to the hypervisor, not
 * with a Read-Only connection.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
int
virConnectGetVersion(virConnectPtr conn, unsigned long *hvVer) {
    unsigned long ver;

    if (!VIR_IS_CONNECT(conn))
	return(-1);
    
    if (hvVer == NULL)
        return(-1);
    
    /* this can't be extracted from the Xenstore */
    if (conn->handle < 0) {
        *hvVer = 0;
        return(0);
    }

    ver = xenHypervisorGetVersion(conn->handle);
    *hvVer = (ver >> 16) * 1000000 + (ver & 0xFFFF) * 1000;
    return(0);
}

/**
 * virConnectListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectListDomains(virConnectPtr conn, int *ids, int maxids) {
    int ret = -1;
    unsigned int num, i;
    long id;
    char **idlist = NULL, *endptr;

    if (!VIR_IS_CONNECT(conn))
	return(-1);
    
    if ((ids == NULL) || (maxids <= 0))
        return(-1);
    
    /* TODO: implement the API with Xend interfaces */
    idlist = xend_get_domains(conn);
    if (idlist != NULL) {
        for (ret = 0,i = 0;(idlist[i] != NULL) && (ret < maxids);i++) {
	    id = xend_get_domain_id(conn, idlist[i]);
	    if (id >= 0)
	        ids[ret++] = (int) id;
	}
	goto done;
    }
    if (conn->xshandle != NULL) {
	idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
	if (idlist == NULL)
	    goto done;

	for (ret = 0,i = 0;(i < num) && (ret < maxids);i++) {
	    id = strtol(idlist[i], &endptr, 10);
	    if ((endptr == idlist[i]) || (*endptr != 0)) {
		ret = -1;
		goto done;
	    }
	    if (virConnectCheckStoreID(conn, (int) id) < 0)
		continue;
	    ids[ret++] = (int) id;
	}
    }

done:
    if (idlist != NULL)
        free(idlist);

    return(ret);
}

/**
 * virConnectNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDomains(virConnectPtr conn) {
    int ret = -1;
    unsigned int num;
    char **idlist = NULL;

    if (!VIR_IS_CONNECT(conn))
	return(-1);

    /* 
     * try first with Xend interface
     */
    idlist = xend_get_domains(conn);
    if (idlist != NULL) {
        char **tmp = idlist;

        ret = 0;
        while (*tmp != NULL) {
	    tmp++;
	    ret++;
	}
	
    } else if (conn->xshandle != NULL) {
        idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
	if (idlist) {
	    free(idlist);
	    ret = num;
	}
    }
    return(ret);
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @kernel_path: the file path to the kernel image
 * @initrd_path: an optional file path to an initrd
 * @cmdline: optional command line parameters for the kernel
 * @memory: the memory size in kilobytes
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain, unimplemented yet, API to be defined.
 * This would function requires priviledged access to the hypervisor.
 * 
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *kernel_path,
		     const char *initrd_path ATTRIBUTE_UNUSED,
		     const char *cmdline ATTRIBUTE_UNUSED,
		     unsigned long memory,
		     unsigned int flags ATTRIBUTE_UNUSED) {

    if (!VIR_IS_CONNECT(conn))
	return(NULL);
    if ((kernel_path == NULL) || (memory < 4096))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * virConnectDoStoreList:
 * @conn: pointer to the hypervisor connection
 * @path: the absolute path of the directory in the store to list
 * @nb: OUT pointer to the number of items found
 *
 * Internal API querying the Xenstore for a list
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char **
virConnectDoStoreList(virConnectPtr conn, const char *path, unsigned int *nb) {
    if ((conn == NULL) || (conn->xshandle == NULL) || (path == NULL) ||
        (nb == NULL))
        return(NULL);

    return xs_directory(conn->xshandle, 0, path, nb);
}

/**
 * virDomainDoStoreQuery:
 * @domain: a domain object
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
virDomainDoStoreQuery(virDomainPtr domain, const char *path) {
    char s[256];
    unsigned int len = 0;
    
    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(NULL);
    if (domain->conn->xshandle == NULL)
        return(NULL);

    snprintf(s, 255, "/local/domain/%d/%s", domain->handle, path);
    s[255] = 0;

    return xs_read(domain->conn->xshandle, 0, &s[0], &len);
}


/**
 * virDomainDoStoreWrite:
 * @domain: a domain object
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API setting up a string value in the Xenstore
 * Requires write access to the XenStore
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainDoStoreWrite(virDomainPtr domain, const char *path,
                      const char *value) {
    char s[256];

    int ret = -1;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    if (domain->conn->xshandle == NULL)
        return(-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return(-1);

    snprintf(s, 255, "/local/domain/%d/%s", domain->handle, path);
    s[255] = 0;

    if (xs_write(domain->conn->xshandle, 0, &s[0], value, strlen(value)))
        ret = 0;

    return(ret);
}

/**
 * virDomainGetVM:
 * @domain: a domain object
 *
 * Internal API extracting a xenstore vm path.
 *
 * Returns the new string or NULL in case of error
 */
char *
virDomainGetVM(virDomainPtr domain)
{
    char *vm;
    char query[200];
    unsigned int len;
    
    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(NULL);
    if (domain->conn->xshandle == NULL)
        return(NULL);
    
    snprintf(query, 199, "/local/domain/%d/vm", 
             virDomainGetID(domain));
    query[199] = 0;

    vm = xs_read(domain->conn->xshandle, 0, &query[0], &len);

    return(vm);
}

/**
 * virDomainGetVMInfo:
 * @domain: a domain object
 * @vm: the xenstore vm path
 * @name: the value's path
 *
 * Internal API extracting one information the device used 
 * by the domain from xensttore
 *
 * Returns the new string or NULL in case of error
 */
char *
virDomainGetVMInfo(virDomainPtr domain, const char *vm, 
                   const char *name) {
    char s[256];
    char *ret = NULL;
    unsigned int len = 0;
    
    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(NULL);
    if (domain->conn->xshandle==NULL)
	return(NULL);
    
    snprintf(s, 255, "%s/%s", vm, name);
    s[255] = 0;

    ret = xs_read(domain->conn->xshandle, 0, &s[0], &len);

    return(ret);
}

/**
 * virDomainLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByID(virConnectPtr conn, int id) {
    char *path = NULL;
    virDomainPtr ret;
    char *name = NULL;

    if (!VIR_IS_CONNECT(conn))
	return(NULL);
    if (id < 0)
        return(NULL);

    /* lookup is easier with the Xen store so try it first */
    if (conn->xshandle != NULL) {
	path = xs_get_domain_path(conn->xshandle, (unsigned int) id);
    }
    /* fallback to xend API then */
    if (path == NULL) {
        char **names = xend_get_domains(conn);
	char **tmp = names;
	int ident;

	if (names != NULL) {
	    while (*tmp != NULL) {
		ident = xend_get_domain_id(conn, *tmp);
		if (ident == id) {
		    name = strdup(*tmp);
		    break;
		}
		tmp++;
	    }
	    free(names);
	}
    }

    ret = (virDomainPtr) malloc(sizeof(virDomain));
    if (ret == NULL) {
        if (path != NULL)
	    free(path);
	return(NULL);
    }
    ret->magic = VIR_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->handle = id;
    ret->path = path;
    if (name == NULL)
	ret->name = virDomainDoStoreQuery(ret, "name");
    else
        ret->name = name;
    if (ret->name == NULL) {
        if (path != NULL)
	    free(path);
        free(ret);
	return(NULL);
    }

    return(ret);
}

/**
 * virDomainLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its name.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByName(virConnectPtr conn, const char *name) {
    virDomainPtr ret = NULL;
    unsigned int num, i, len;
    long id = -1;
    char **idlist = NULL, *endptr;
    char prop[200], *tmp, *path = NULL;
    unsigned char *uuid = NULL;
    int found = 0;
    struct xend_domain *xenddomain = NULL;

    if (!VIR_IS_CONNECT(conn))
	return(NULL);
    if (name == NULL)
        return(NULL);

    /* try first though Xend */
    xenddomain = xend_get_domain(conn, name);
    if (xenddomain != NULL) {
        id = xenddomain->live->id;
	uuid = xenddomain->uuid;
	found = 1;
	goto do_found;
    }

    /* then though the XenStore */
    if (conn->xshandle != NULL) {
        idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
        if (idlist == NULL)
            goto done;

        for (i = 0;i < num;i++) {
             id = strtol(idlist[i], &endptr, 10);
	     if ((endptr == idlist[i]) || (*endptr != 0)) {
	         goto done;
	     }
	     if (virConnectCheckStoreID(conn, (int) id) < 0)
	         continue;
             snprintf(prop, 199, "/local/domain/%s/name", idlist[i]);
	     prop[199] = 0;
	     tmp = xs_read(conn->xshandle, 0, prop, &len);
	     if (tmp != NULL) {
	         found = !strcmp(name, tmp);
	         free(tmp);
	         if (found)
	             break;
	     }
        }
        path = xs_get_domain_path(conn->xshandle, (unsigned int) id);
    }

do_found:

    if (found) {
	ret = (virDomainPtr) malloc(sizeof(virDomain));
	if (ret == NULL)
	    goto done;
	ret->magic = VIR_DOMAIN_MAGIC;
	ret->conn = conn;
	ret->handle = id;
	ret->path = path;
	if (uuid != NULL)
	    memcpy(ret->uuid, uuid, 16);
	ret->name = strdup(name);
    }

done:
    if (xenddomain != NULL)
	free(xenddomain);
    if (idlist != NULL)
        free(idlist);

    return(ret);
}

/**
 * virDomainDestroy:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 * The data structure is freed and should not be used thereafter if the
 * call does not return an error.
 * This function may requires priviledged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain) {
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);

    /*
     * try first with the xend method
     */
    ret = xend_destroy(domain->conn, domain->name);
    if (ret == 0) {
        virDomainFree(domain);
	return(0);
    }

    ret = xenHypervisorDestroyDomain(domain->conn->handle, domain->handle);
    if (ret < 0)
        return(-1);
    
    virDomainFree(domain);
    return(0);
}

/**
 * virDomainFree:
 * @domain: a domain object
 *
 * Free the domain object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainFree(virDomainPtr domain) {
    if (!VIR_IS_DOMAIN(domain))
	return(-1);
    domain->magic = -1;
    domain->handle = -1;
    if (domain->path != NULL)
        free(domain->path);
    if (domain->name)
        free(domain->name);
    free(domain);
    return(0);
}

/**
 * virDomainSuspend:
 * @domain: a domain object
 *
 * Suspends an active domain, the process is frozen without further access
 * to CPU resources and I/O but the memory used by the domain at the 
 * hypervisor level will stay allocated. Use virDomainResume() to reactivate
 * the domain.
 * This function may requires priviledged access.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain) {
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    /* first try though the Xen daemon */
    ret = xend_pause(domain->conn, domain->name);
    if (ret == 0)
        return(0);

    /* then try a direct hypervisor access */
    return(xenHypervisorPauseDomain(domain->conn->handle, domain->handle));
}

/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume an suspended domain, the process is restarted from the state where
 * it was frozen by calling virSuspendDomain().
 * This function may requires priviledged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain) {
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    /* first try though the Xen daemon */
    ret = xend_unpause(domain->conn, domain->name);
    if (ret == 0)
        return(0);

    /* then try a direct hypervisor access */
    return(xenHypervisorResumeDomain(domain->conn->handle, domain->handle));
}

/**
 * virDomainSave:
 * @domain: a domain object
 * @to: path for the output file
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this may be a problem).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSave(virDomainPtr domain, const char *to) {
    int ret;
    char filepath[4096];

    if ((!VIR_IS_CONNECTED_DOMAIN(domain)) || (to == NULL))
	return(-1);

    /*
     * We must absolutize the file path as the save is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (to[0] != '/') {
	unsigned int len, t;

	t = strlen(to);
	if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL)
	    return(-1);
	len = strlen(filepath);
	/* that should be covered by getcwd() semantic, but be 100% sure */
	if (len > sizeof(filepath) - (t + 3))
	    return(-1); 
	filepath[len] = '/';
	strcpy(&filepath[len + 1], to);
	to = &filepath[0];

    }

    ret = xend_save(domain->conn, domain->name, to);
    return(ret);
}

/**
 * virDomainRestore:
 * @conn: pointer to the hypervisor connection
 * @from: path to the 
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestore(virConnectPtr conn, const char *from) {
    int ret;
    char filepath[4096];

    if ((!VIR_IS_CONNECT(conn)) || (from == NULL))
	return(-1);
    /*
     * We must absolutize the file path as the restore is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (from[0] != '/') {
	unsigned int len, t;

	t = strlen(from);
	if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL)
	    return(-1);
	len = strlen(filepath);
	/* that should be covered by getcwd() semantic, but be 100% sure */
	if (len > sizeof(filepath) - (t + 3))
	    return(-1); 
	filepath[len] = '/';
	strcpy(&filepath[len + 1], from);
	from = &filepath[0];
    }
    
    ret = xend_restore(conn, from);
    return(ret);
}

/**
 * virDomainShutdown:
 * @domain: a domain object
 *
 * Shutdown a domain, the domain object is still usable there after but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request.
 *
 * TODO: should we add an option for reboot, knowing it may not be doable
 *       in the general case ?
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdown(virDomainPtr domain) {
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    
    /*
     * try first with the xend daemon
     */
    ret = xend_shutdown(domain->conn, domain->name);
    /* disabled as this seems to not work ...
    if (ret == 0)
        return(0);
     */
    /*

     * this is very hackish, the domU kernel probes for a special 
     * node in the xenstore and launch the shutdown command if found.
     */
    ret = virDomainDoStoreWrite(domain, "control/shutdown", "halt");
    if (ret == 0) {
        domain->flags |= DOMAIN_IS_SHUTDOWN;
    }
    return(ret);
}

/**
 * virDomainGetName:
 * @domain: a domain object
 *
 * Get the public name for that domain
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the domain object.
 */
const char *
virDomainGetName(virDomainPtr domain) {
    if (!VIR_IS_DOMAIN(domain))
	return(NULL);
    return(domain->name);
}

/**
 * virDomainGetID:
 * @domain: a domain object
 *
 * Get the hypervisor ID number for the domain
 *
 * Returns the domain ID number or (unsigned int) -1 in case of error
 */
unsigned int
virDomainGetID(virDomainPtr domain) {
    if (!VIR_IS_DOMAIN(domain))
	return((unsigned int) -1);
    return(domain->handle);
}

/**
 * virDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error
 */
char *
virDomainGetOSType(virDomainPtr domain) {
    char *vm, *str = NULL;
    
    if (!VIR_IS_DOMAIN(domain))
	return(NULL);
    
    vm = virDomainGetVM(domain);
    if (vm) {
    	str = virDomainGetVMInfo(domain, vm, "image/ostype");
	free(vm);
    }
    if (str == NULL)
        str = strdup("linux");

    return(str);
}

/**
 * virDomainGetMaxMemory:
 * @domain: a domain object or NULL
 * 
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
virDomainGetMaxMemory(virDomainPtr domain) {
    unsigned long ret = 0;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(0);
    
    if (domain->conn->flags & VIR_CONNECT_RO) {
        char *tmp;

	tmp = virDomainDoStoreQuery(domain, "memory/target");
	if (tmp != NULL) {
	    ret = (unsigned long) atol(tmp);
	    free(tmp);
	}
    } else {
        dom0_getdomaininfo_t dominfo;
	int tmp;

	dominfo.domain = domain->handle;
        tmp = xenHypervisorGetDomainInfo(domain->conn->handle, domain->handle,
	                                 &dominfo);
	if (tmp >= 0)
	    ret = dominfo.max_pages * 4;
    }
    return(ret);
}

/**
 * virDomainSetMaxMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kilobytes
 * 
 * Dynamically change the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function requires priviledged access to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory) {
    int ret;
    char s[256], v[30];
    
    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    if (memory < 4096)
        return(-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return(-1);
    if (domain->conn->xshandle==NULL)
	return(-1);
    ret = xenHypervisorSetMaxMemory(domain->conn->handle, domain->handle,
                                    memory);
    if (ret < 0)
        return(-1);

    /*
     * try to update at the Xenstore level too
     * Failing to do so should not be considered fatal though as long
     * as the hypervisor call succeeded
     */
    snprintf(s, 255, "/local/domain/%d/memory/target", domain->handle);
    s[255] = 0;
    snprintf(v, 29, "%lu", memory);
    v[30] = 0;

    if (!xs_write(domain->conn->xshandle, 0, &s[0], &v[0], strlen(v)))
        ret = -1;

    return(ret);
}

/**
 * virDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 * 
 * Extract information about a domain. Note that if the connection
 * used to get the domain is limited only a partial set of the informations
 * can be extracted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info) {
    int ret;
    char *tmp, **tmp2;
    unsigned int nb_vcpus;
    char request[200];


    if (!VIR_IS_CONNECTED_DOMAIN(domain))
	return(-1);
    if (info == NULL)
	return(-1);
    
    memset(info, 0, sizeof(virDomainInfo));
    
    /*
     * if we have direct access though the hypervisor do a direct call
     */
    if (domain->conn->handle >= 0) {
        dom0_getdomaininfo_t dominfo;

	dominfo.domain = domain->handle;
        ret = xenHypervisorGetDomainInfo(domain->conn->handle, domain->handle,
	                                 &dominfo);
        if (ret < 0)
	    goto xend_info;

	switch (dominfo.flags & 0xFF) {
	    case DOMFLAGS_DYING:
	        info->state = VIR_DOMAIN_SHUTDOWN;
		break;
	    case DOMFLAGS_SHUTDOWN:
	        info->state = VIR_DOMAIN_SHUTOFF;
		break;
	    case DOMFLAGS_PAUSED:
	        info->state = VIR_DOMAIN_PAUSED;
		break;
	    case DOMFLAGS_BLOCKED:
	        info->state = VIR_DOMAIN_BLOCKED;
		break;
	    case DOMFLAGS_RUNNING:
	        info->state = VIR_DOMAIN_RUNNING;
		break;
	    default:
	        info->state = VIR_DOMAIN_NONE;
	}

	/*
	 * the API brings back the cpu time in nanoseconds,
	 * convert to microseconds, same thing convert to
         * kilobytes from page counts
	 */
	info->cpuTime = dominfo.cpu_time;
	info->memory = dominfo.tot_pages * 4;
	info->maxMem = dominfo.max_pages * 4;
	info->nrVirtCpu = dominfo.nr_online_vcpus;
	return(0);
    }

xend_info:
    /*
     * try to extract the informations though access to the Xen Daemon
     */
    if (xend_get_domain_info(domain, info) == 0)
        return(0);

    /*
     * last fallback, try to get the inforamtions from the Xen store
     */

    tmp = virDomainDoStoreQuery(domain, "running");
    if (tmp != NULL) {
	if (tmp[0] == '1')
	    info->state = VIR_DOMAIN_RUNNING;
	free(tmp);
    } else {
	info->state = VIR_DOMAIN_NONE;
    }
    tmp = virDomainDoStoreQuery(domain, "memory/target");
    if (tmp != NULL) {
	info->memory = atol(tmp);
	info->maxMem = atol(tmp);
	free(tmp);
    } else {
	info->memory = 0;
	info->maxMem = 0;
    }
#if 0
    /* doesn't seems to work */
    tmp = virDomainDoStoreQuery(domain, "cpu_time");
    if (tmp != NULL) {
	info->cpuTime = atol(tmp);
	free(tmp);
    } else {
	info->cpuTime = 0;
    }
#endif
    snprintf(request, 199, "/local/domain/%d/cpu", domain->handle);
    request[199] = 0;
    tmp2 = virConnectDoStoreList(domain->conn, request, &nb_vcpus);
    if (tmp2 != NULL) {
	info->nrVirtCpu = nb_vcpus;
	free(tmp2);
    }
    return(0);
}

