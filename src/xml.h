/*
 * xml.h: internal definitions used for XML parsing routines.
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "libvirt/libvirt.h"
#include "internal.h"
#include "buf.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#ifdef __cplusplus
extern "C" {
#endif

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

#if WITH_XEN || WITH_QEMU
int		virParseCpuSet	(virConnectPtr conn,
                                 const char **str,
                                 char sep,
                                 char *cpuset,
                                 int maxcpu);
char *          virSaveCpuSet	(virConnectPtr conn,
                                 char *cpuset,
                                 int maxcpu);
#endif
#if WITH_XEN
char *		virConvertCpuSet(virConnectPtr conn,
                                 const char *str,
                                 int maxcpu);
int             virDomainParseXMLOSDescHVMChar(virConnectPtr conn,
                                               char *buf,
                                               size_t buflen,
                                               xmlNodePtr node);
char *		virDomainParseXMLDesc(virConnectPtr conn,
                                 const char *xmldesc,
                                 char **name,
                                 int xendConfigVersion);
char *		virParseXMLDevice(virConnectPtr conn,
                                 const char *xmldesc,
                                 int hvm,
                                 int xendConfigVersion);
int		virDomainXMLDevID(virDomainPtr domain,
                                 const char *xmldesc,
                                 char *class,
                                 char *ref,
                                 int ref_len);
char * virBuildSoundStringFromXML(virConnectPtr conn,
                                  xmlXPathContextPtr ctxt);
#endif

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_XML_H__ */
