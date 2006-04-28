/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "libvirt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;
struct _virBuffer {
    char *content;          /* The buffer content UTF8 */
    unsigned int use;       /* The buffer size used */
    unsigned int size;      /* The buffer size */
};

int virBufferAdd(virBufferPtr buf, const char *str, int len);
int virBufferVSprintf(virBufferPtr buf, const char *format, ...);
char *virDomainParseXMLDesc(const char *xmldesc, char **name);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_XML_H__ */
