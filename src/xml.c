/*
 * xml.c: XML based interfaces for the libvir library
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
#include <stdarg.h>
#include <xs.h>
#include "internal.h"
#include "hash.h"

/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;
struct _virBuffer {
    char *content;		/* The buffer content UTF8 */
    unsigned int use;		/* The buffer size used */
    unsigned int size;		/* The buffer size */
};

/**
 * virBufferGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate
 *
 * Grow the available space of an XML buffer.
 *
 * Returns the new available space or -1 in case of error
 */
static int
virBufferGrow(virBufferPtr buf, unsigned int len) {
    int size;
    char *newbuf;

    if (buf == NULL) return(-1);
    if (len + buf->use < buf->size) return(0);

    size = buf->use + len + 1000;

    newbuf = (char *) realloc(buf->content, size);
    if (newbuf == NULL) {
        return(-1);
    }
    buf->content = newbuf;
    buf->size = size;
    return(buf->size - buf->use);
}

/**
 * virBufferAdd:
 * @buf:  the buffer to dump
 * @str:  the string
 * @len:  the number of bytes to add
 *
 * Add a string range to an XML buffer. if len == -1, the length of
 * str is recomputed to the full string.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
static int
virBufferAdd(virBufferPtr buf, const char *str, int len) {
    unsigned int needSize;

    if ((str == NULL) || (buf == NULL)) {
	return -1;
    }
    if (len == 0) return 0;

    if (len < 0)
        len = strlen(str);

    needSize = buf->use + len + 2;
    if (needSize > buf->size){
        if (!virBufferGrow(buf, needSize)){
            return(-1);
        }
    }

    memmove(&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;
    return(0);
}

/**
 * virBufferVSprintf:
 * @buf:  the buffer to dump
 * @format:  the format
 * @argptr:  the variable list of arguments
 *
 * Do a formatted print to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
static int
virBufferVSprintf(virBufferPtr buf, const char *format, ...) {
    int size, count;
    va_list locarg, argptr;

    if ((format == NULL) || (buf == NULL)) {
	return(-1);
    }
    size = buf->size - buf->use - 1;
    va_start(argptr, format);
    va_copy(locarg, argptr);
    while (((count = vsnprintf(&buf->content[buf->use], size, format,
                               locarg)) < 0) || (count >= size - 1)) {
	buf->content[buf->use] = 0;
	va_end(locarg);
	if (virBufferGrow(buf, 1000) < 0) {
	    return(-1);
	}
	size = buf->size - buf->use - 1;
	va_copy(locarg, argptr);
    }
    va_end(locarg);
    buf->use += count;
    buf->content[buf->use] = 0;
    return(0);
}

/**
 * virDomainGetXMLDevice:
 * @domain: a domain object
 * @sub: the xenstore subsection 'vbd', 'vif', ...
 * @dev: the xenstrore internal device number
 * @name: the value's name
 *
 * Extract one information the device used by the domain from xensttore
 *
 * Returns the new string or NULL in case of error
 */
static char *
virDomainGetXMLDeviceInfo(virDomainPtr domain, const char *sub, 
                          long dev, const char *name) {
    struct xs_transaction_handle* t;
    char s[256];
    char *ret = NULL;
    unsigned int len = 0;

    snprintf(s, 255, "/local/domain/0/backend/%s/%d/%ld/%s",
             sub, domain->handle, dev, name);
    s[255] = 0;

    t = xs_transaction_start(domain->conn->xshandle);
    if (t == NULL)
        goto done;

    ret = xs_read(domain->conn->xshandle, t, &s[0], &len);

done:
    if (t != NULL)
	xs_transaction_end(domain->conn->xshandle, t, 0);
    return(ret);
}

/**
 * virDomainGetXMLDevice:
 * @domain: a domain object
 * @buf: the output buffer object
 * @dev: the xenstrore internal device number
 *
 * Extract and dump in the buffer informations on the device used by the domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLDevice(virDomainPtr domain, virBufferPtr buf, long dev) {
    char *type, *val;

    type = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "type");
    if (type == NULL)
        return(-1);
    if (!strcmp(type, "file")) {
	virBufferVSprintf(buf, "    <disk type='file'>\n");
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "params");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <source file='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "dev");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <target dev='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "read-only");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <readonly/>\n", val);
	    free(val);
	}
	virBufferAdd(buf, "    </disk>\n", 12);
    } else if (!strcmp(type, "phy")) {
	virBufferVSprintf(buf, "    <disk type='device'>\n");
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "params");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <source device='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "dev");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <target dev='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "read-only");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <readonly/>\n", val);
	    free(val);
	}
	virBufferAdd(buf, "    </disk>\n", 12);
    } else {
        TODO
	fprintf(stderr, "Don't know how to handle device type %s\n", type);
    }
    free(type);

    return(0);
}

/**
 * virDomainGetXMLDevices:
 * @domain: a domain object
 * @buf: the output buffer object
 *
 * Extract the devices used by the domain and dumps then in the buffer
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLDevices(virDomainPtr domain, virBufferPtr buf) {
    struct xs_transaction_handle* t;
    int ret = -1;
    unsigned int num, i;
    long id;
    char **list = NULL, *endptr;
    char backend[200];
    virConnectPtr conn;

    conn = domain->conn;

    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC))
        return(-1);
    
    t = xs_transaction_start(conn->xshandle);
    if (t == NULL)
        goto done;

    snprintf(backend, 199, "/local/domain/0/backend/vbd/%d", 
             virDomainGetID(domain));
    backend[199] = 0;
    list = xs_directory(conn->xshandle, t, backend, &num);
    ret = 0;
    if (list == NULL)
        goto done;

    for (i = 0;i < num;i++) {
        id = strtol(list[i], &endptr, 10);
	if ((endptr == list[i]) || (*endptr != 0)) {
	    ret = -1;
	    goto done;
	}
	virDomainGetXMLDevice(domain, buf, id);
    }

done:
    if (t != NULL)
	xs_transaction_end(conn->xshandle, t, 0);
    if (list != NULL)
        free(list);

    return(ret);
}

/**
 * virDomainGetXMLInterface:
 * @domain: a domain object
 * @buf: the output buffer object
 * @dev: the xenstrore internal device number
 *
 * Extract and dump in the buffer informations on the interface used by
 * the domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLInterface(virDomainPtr domain, virBufferPtr buf, long dev) {
    char *type, *val;

    type = virDomainGetXMLDeviceInfo(domain, "vif", dev, "bridge");
    if (type == NULL) {
	virBufferVSprintf(buf, "    <interface type='default'>\n");
	val = virDomainGetXMLDeviceInfo(domain, "vif", dev, "mac");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <mac address='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vif", dev, "script");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <script path='%s'/>\n", val);
	    free(val);
	}
	virBufferAdd(buf, "    </interface>\n", 17);
    } else {
	virBufferVSprintf(buf, "    <interface type='bridge'>\n");
	virBufferVSprintf(buf, "      <source bridge='%s'/>\n", type);
	val = virDomainGetXMLDeviceInfo(domain, "vif", dev, "mac");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <mac address='%s'/>\n", val);
	    free(val);
	}
	val = virDomainGetXMLDeviceInfo(domain, "vif", dev, "script");
	if (val != NULL) {
	    virBufferVSprintf(buf, "      <script path='%s'/>\n", val);
	    free(val);
	}
	virBufferAdd(buf, "    </interface>\n", 17);
    }
    free(type);

    return(0);
}

/**
 * virDomainGetXMLInterfaces:
 * @domain: a domain object
 * @buf: the output buffer object
 *
 * Extract the interfaces used by the domain and dumps then in the buffer
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLInterfaces(virDomainPtr domain, virBufferPtr buf) {
    struct xs_transaction_handle* t;
    int ret = -1;
    unsigned int num, i;
    long id;
    char **list = NULL, *endptr;
    char backend[200];
    virConnectPtr conn;

    conn = domain->conn;

    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC))
        return(-1);
    
    t = xs_transaction_start(conn->xshandle);
    if (t == NULL)
        goto done;

    snprintf(backend, 199, "/local/domain/0/backend/vif/%d", 
             virDomainGetID(domain));
    backend[199] = 0;
    list = xs_directory(conn->xshandle, t, backend, &num);
    ret = 0;
    if (list == NULL)
        goto done;

    for (i = 0;i < num;i++) {
        id = strtol(list[i], &endptr, 10);
	if ((endptr == list[i]) || (*endptr != 0)) {
	    ret = -1;
	    goto done;
	}
	virDomainGetXMLInterface(domain, buf, id);
    }

done:
    if (t != NULL)
	xs_transaction_end(conn->xshandle, t, 0);
    if (list != NULL)
        free(list);

    return(ret);
}




/**
 * virDomainGetXMLBoot:
 * @domain: a domain object
 * @buf: the output buffer object
 *
 * Extract the boot informations used to start that domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLBoot(virDomainPtr domain, virBufferPtr buf) {
    char *vm, *str;

    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(-1);
    
    vm = virDomainGetVM(domain);
    if (vm == NULL)
        return(-1);

    virBufferAdd(buf, "  <os>\n", 7);
    str = virDomainGetVMInfo(domain, vm, "image/ostype");
    if (str != NULL) {
        virBufferVSprintf(buf, "    <type>%s</type>\n", str);
        free(str);
    }
    str = virDomainGetVMInfo(domain, vm, "image/kernel");
    if (str != NULL) {
        virBufferVSprintf(buf, "    <kernel>%s</kernel>\n", str);
        free(str);
    }
    str = virDomainGetVMInfo(domain, vm, "image/ramdisk");
    if (str != NULL) {
	if (str[0] != 0)
	    virBufferVSprintf(buf, "    <initrd>%s</initrd>\n", str);
        free(str);
    }
    str = virDomainGetVMInfo(domain, vm, "image/cmdline");
    if (str != NULL) {
	if (str[0] != 0)
	    virBufferVSprintf(buf, "    <cmdline>%s</cmdline>\n", str);
        free(str);
    }
    virBufferAdd(buf, "  </os>\n", 8);

    free(vm);
    return(0);
}

/**
 * virDomainGetXMLDesc:
 * @domain: a domain object
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * Provide an XML description of the domain. NOTE: this API is subject
 * to changes.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainGetXMLDesc(virDomainPtr domain, int flags) {
    char *ret = NULL;
    virBuffer buf;
    virDomainInfo info;

    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC) ||
        (flags != 0))
	return(NULL);

    if (virDomainGetInfo(domain, &info) < 0)
        return(NULL);

    ret = malloc(1000);
    if (ret == NULL)
        return(NULL);
    buf.content = ret;
    buf.size = 1000;
    buf.use = 0;

    virBufferVSprintf(&buf, "<domain type='xen' id='%d'>\n",
                      virDomainGetID(domain));
    virBufferVSprintf(&buf, "  <name>%s</name>\n", virDomainGetName(domain));
    virDomainGetXMLBoot(domain, &buf);
    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", info.maxMem);
    virBufferVSprintf(&buf, "  <vcpu>%d</vcpu>\n", (int) info.nrVirtCpu);
    virBufferAdd(&buf, "  <devices>\n", 12);
    virDomainGetXMLDevices(domain, &buf);
    virDomainGetXMLInterfaces(domain, &buf);
    virBufferAdd(&buf, "  </devices>\n", 13);
    virBufferAdd(&buf, "</domain>\n", 10);
    
    buf.content[buf.use] = 0;
    return(ret);
}
