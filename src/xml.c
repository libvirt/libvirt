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
    virBufferAdd(&buf, "</domain>\n", 10);
    
    buf.content[buf.use] = 0;
    return(ret);
}
