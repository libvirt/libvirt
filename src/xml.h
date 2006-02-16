/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "libvirt.h"

#ifdef __cplusplus
extern "C" {
#endif

char *	virDomainParseXMLDesc	(const char *xmldesc,
				 char **name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VIR_XML_H__ */

