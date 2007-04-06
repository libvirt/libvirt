/*
 * xml.h: internal definitions used for XML parsing routines.
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "libvirt/libvirt.h"
#include "internal.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
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

virBufferPtr virBufferNew(unsigned int size);
void virBufferFree(virBufferPtr buf);
int virBufferAdd(virBufferPtr buf, const char *str, int len);
int virBufferVSprintf(virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FORMAT(printf, 2, 3);
int virBufferStrcat(virBufferPtr buf, ...);

int		virXPathBoolean	(const char *xpath,
				 xmlXPathContextPtr ctxt);
char *		virXPathString	(const char *xpath,
				 xmlXPathContextPtr ctxt);
int		virXPathNumber	(const char *xpath,
				 xmlXPathContextPtr ctxt,
				 double *value);
int		virXPathLong	(const char *xpath,
				 xmlXPathContextPtr ctxt,
				 long *value);
xmlNodePtr	virXPathNode	(const char *xpath,
				 xmlXPathContextPtr ctxt);
int		virXPathNodeSet	(const char *xpath,
				 xmlXPathContextPtr ctxt,
				 xmlNodePtr **list);

char *virDomainParseXMLDesc(virConnectPtr conn, const char *xmldesc, char **name, int xendConfigVersion);
unsigned char *virParseUUID(char **ptr, const char *uuid);
char *virParseXMLDevice(virConnectPtr conn, char *xmldesc, int hvm, int xendConfigVersion);
int virDomainXMLDevID(virDomainPtr domain, char *xmldesc, char *class, char *ref);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_XML_H__ */
