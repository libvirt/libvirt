/*
 * xml.c: XML based interfaces for the libvir library
 *
 * Copyright (C) 2005, 2007, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include "libvirt/libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#ifdef WITH_XEN
#include <xs.h>
#endif
#include <math.h>               /* for isnan() */
#include "internal.h"
#include "hash.h"
#include "sexpr.h"
#include "xml.h"
#include "buf.h"
#include "util.h"
#include "xs_internal.h"        /* for xenStoreDomainGetNetworkID */
#include "xen_unified.h"

/**
 * virXMLError:
 * @conn: a connection if any
 * @error: the error number
 * @info: information/format string
 * @value: extra integer parameter for the error string
 *
 * Report an error coming from the XML module.
 */
static void
virXMLError(virConnectPtr conn, virErrorNumber error, const char *info,
            int value)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_XML, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}

/************************************************************************
 *									*
 * Parser and converter for the CPUset strings used in libvirt		*
 *									*
 ************************************************************************/
#if WITH_XEN
/**
 * parseCpuNumber:
 * @str: pointer to the char pointer used
 * @maxcpu: maximum CPU number allowed
 *
 * Parse a CPU number
 *
 * Returns the CPU number or -1 in case of error. @str will be
 *         updated to skip the number.
 */
static int
parseCpuNumber(const char **str, int maxcpu)
{
    int ret = 0;
    const char *cur = *str;

    if ((*cur < '0') || (*cur > '9'))
        return (-1);

    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
        if (ret >= maxcpu)
            return (-1);
        cur++;
    }
    *str = cur;
    return (ret);
}

/**
 * virSaveCpuSet:
 * @conn: connection
 * @cpuset: pointer to a char array for the CPU set
 * @maxcpu: number of elements available in @cpuset
 *
 * Serialize the cpuset to a string
 *
 * Returns the new string NULL in case of error. The string need to be
 *         freed by the caller.
 */
char *
virSaveCpuSet(virConnectPtr conn, char *cpuset, int maxcpu)
{
    virBufferPtr buf;
    char *ret;
    int start, cur;
    int first = 1;

    if ((cpuset == NULL) || (maxcpu <= 0) || (maxcpu > 100000))
        return (NULL);

    buf = virBufferNew(1000);
    if (buf == NULL) {
        virXMLError(conn, VIR_ERR_NO_MEMORY, _("allocate buffer"), 1000);
        return (NULL);
    }
    cur = 0;
    start = -1;
    while (cur < maxcpu) {
        if (cpuset[cur]) {
            if (start == -1)
                start = cur;
        } else if (start != -1) {
            if (!first)
                virBufferAddLit(buf, ",");
            else
                first = 0;
            if (cur == start + 1)
                virBufferVSprintf(buf, "%d", start);
            else
                virBufferVSprintf(buf, "%d-%d", start, cur - 1);
            start = -1;
        }
        cur++;
    }
    if (start != -1) {
        if (!first)
            virBufferAddLit(buf, ",");
        if (maxcpu == start + 1)
            virBufferVSprintf(buf, "%d", start);
        else
            virBufferVSprintf(buf, "%d-%d", start, maxcpu - 1);
    }
    ret = virBufferContentAndFree(buf);
    return (ret);
}

/**
 * virParseCpuSet:
 * @conn: connection
 * @str: pointer to a CPU set string pointer
 * @sep: potential character used to mark the end of string if not 0
 * @cpuset: pointer to a char array for the CPU set
 * @maxcpu: number of elements available in @cpuset
 *
 * Parse the cpu set, it will set the value for enabled CPUs in the @cpuset
 * to 1, and 0 otherwise. The syntax allows coma separated entries each
 * can be either a CPU number, ^N to unset that CPU or N-M for ranges.
 *
 * Returns the number of CPU found in that set, or -1 in case of error.
 *         @cpuset is modified accordingly to the value parsed.
 *         @str is updated to the end of the part parsed
 */
int
virParseCpuSet(virConnectPtr conn, const char **str, char sep,
               char *cpuset, int maxcpu)
{
    const char *cur;
    int ret = 0;
    int i, start, last;
    int neg = 0;

    if ((str == NULL) || (cpuset == NULL) || (maxcpu <= 0) ||
        (maxcpu > 100000))
        return (-1);

    cur = *str;
    virSkipSpaces(&cur);
    if (*cur == 0)
        goto parse_error;

    /* initialize cpumap to all 0s */
    for (i = 0; i < maxcpu; i++)
        cpuset[i] = 0;
    ret = 0;

    while ((*cur != 0) && (*cur != sep)) {
        /*
         * 3 constructs are allowed:
         *     - N   : a single CPU number
         *     - N-M : a range of CPU numbers with N < M
         *     - ^N  : remove a single CPU number from the current set
         */
        if (*cur == '^') {
            cur++;
            neg = 1;
        }

        if ((*cur < '0') || (*cur > '9'))
            goto parse_error;
        start = parseCpuNumber(&cur, maxcpu);
        if (start < 0)
            goto parse_error;
        virSkipSpaces(&cur);
        if ((*cur == ',') || (*cur == 0) || (*cur == sep)) {
            if (neg) {
                if (cpuset[start] == 1) {
                    cpuset[start] = 0;
                    ret--;
                }
            } else {
                if (cpuset[start] == 0) {
                    cpuset[start] = 1;
                    ret++;
                }
            }
        } else if (*cur == '-') {
            if (neg)
                goto parse_error;
            cur++;
            virSkipSpaces(&cur);
            last = parseCpuNumber(&cur, maxcpu);
            if (last < start)
                goto parse_error;
            for (i = start; i <= last; i++) {
                if (cpuset[i] == 0) {
                    cpuset[i] = 1;
                    ret++;
                }
            }
            virSkipSpaces(&cur);
        }
        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            neg = 0;
        } else if ((*cur == 0) || (*cur == sep)) {
            break;
        } else
            goto parse_error;
    }
    *str = cur;
    return (ret);

  parse_error:
    virXMLError(conn, VIR_ERR_XEN_CALL,
                _("topology cpuset syntax error"), 0);
    return (-1);
}


/**
 * virConvertCpuSet:
 * @conn: connection
 * @str: pointer to a Xen or user provided CPU set string pointer
 * @maxcpu: number of CPUs on the node, if 0 4096 will be used
 *
 * Parse the given CPU set string and convert it to a range based
 * string.
 *
 * Returns a new string which must be freed by the caller or NULL in
 *         case of error.
 */
char *
virConvertCpuSet(virConnectPtr conn, const char *str, int maxcpu) {
    int ret;
    char *res, *cpuset;
    const char *cur = str;

    if (str == NULL)
        return(NULL);

    if (maxcpu <= 0)
        maxcpu = 4096;

    cpuset = calloc(maxcpu, sizeof(*cpuset));
    if (cpuset == NULL) {
	virXMLError(conn, VIR_ERR_NO_MEMORY, _("allocate buffer"), 0);
	return(NULL);
    }

    ret = virParseCpuSet(conn, &cur, 0, cpuset, maxcpu);
    if (ret < 0) {
        free(cpuset);
	return(NULL);
    }
    res = virSaveCpuSet(conn, cpuset, maxcpu);
    free(cpuset);
    return (res);
}
#endif /* WITH_XEN */
#ifndef PROXY

/************************************************************************
 *									*
 * Wrappers around libxml2 XPath specific functions			*
 *									*
 ************************************************************************/

/**
 * virXPathString:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath string
 *
 * Returns a new string which must be deallocated by the caller or NULL
 *         if the evaluation failed.
 */
char *
virXPathString(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    char *ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathString()"), 0);
        return (NULL);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        xmlXPathFreeObject(obj);
        return (NULL);
    }
    ret = strdup((char *) obj->stringval);
    xmlXPathFreeObject(obj);
    if (ret == NULL) {
        virXMLError(NULL, VIR_ERR_NO_MEMORY, _("strdup failed"), 0);
    }
    return (ret);
}

/**
 * virXPathNumber:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned double value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the evaluation failed.
 */
int
virXPathNumber(const char *xpath, xmlXPathContextPtr ctxt, double *value)
{
    xmlXPathObjectPtr obj;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNumber()"), 0);
        return (-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval))) {
        xmlXPathFreeObject(obj);
        return (-1);
    }

    *value = obj->floatval;
    xmlXPathFreeObject(obj);
    return (0);
}

/**
 * virXPathLong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathLong(const char *xpath, xmlXPathContextPtr ctxt, long *value)
{
    xmlXPathObjectPtr obj;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNumber()"), 0);
        return (-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        char *conv = NULL;
        long val;

        val = strtol((const char *) obj->stringval, &conv, 10);
        if (conv == (const char *) obj->stringval) {
            ret = -2;
        } else {
            *value = val;
        }
    } else if ((obj != NULL) && (obj->type == XPATH_NUMBER) &&
               (!(isnan(obj->floatval)))) {
        *value = (long) obj->floatval;
        if (*value != obj->floatval) {
            ret = -2;
        }
    } else {
        ret = -1;
    }

    xmlXPathFreeObject(obj);
    return (ret);
}

/**
 * virXPathBoolean:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath boolean
 *
 * Returns 0 if false, 1 if true, or -1 if the evaluation failed.
 */
int
virXPathBoolean(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathBoolean()"), 0);
        return (-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN) ||
        (obj->boolval < 0) || (obj->boolval > 1)) {
        xmlXPathFreeObject(obj);
        return (-1);
    }
    ret = obj->boolval;

    xmlXPathFreeObject(obj);
    return (ret);
}

/**
 * virXPathNode:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath node set and returning
 * only one node, the first one in the set if any
 *
 * Returns a pointer to the node or NULL if the evaluation failed.
 */
xmlNodePtr
virXPathNode(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNode()"), 0);
        return (NULL);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
        (obj->nodesetval->nodeTab == NULL)) {
        xmlXPathFreeObject(obj);
        return (NULL);
    }

    ret = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    return (ret);
}

/**
 * virXPathNodeSet:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @list: the returned list of nodes (or NULL if only count matters)
 *
 * Convenience function to evaluate an XPath node set
 *
 * Returns the number of nodes found in which case @list is set (and
 *         must be freed) or -1 if the evaluation failed.
 */
int
virXPathNodeSet(const char *xpath, xmlXPathContextPtr ctxt,
                xmlNodePtr ** list)
{
    xmlXPathObjectPtr obj;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNodeSet()"), 0);
        return (-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
        (obj->nodesetval->nodeTab == NULL)) {
        xmlXPathFreeObject(obj);
        if (list != NULL)
            *list = NULL;
        return (-1);
    }

    ret = obj->nodesetval->nodeNr;
    if (list != NULL) {
        *list = malloc(ret * sizeof(**list));
        if (*list == NULL) {
            virXMLError(NULL, VIR_ERR_NO_MEMORY,
                        _("allocate string array"),
                        ret * sizeof(**list));
        } else {
            memcpy(*list, obj->nodesetval->nodeTab,
                   ret * sizeof(xmlNodePtr));
        }
    }
    xmlXPathFreeObject(obj);
    return (ret);
}

/************************************************************************
 *									*
 * Converter functions to go from the XML tree to an S-Expr for Xen	*
 *									*
 ************************************************************************/
#if WITH_XEN
/**
 * virtDomainParseXMLGraphicsDescImage:
 * @conn: pointer to the hypervisor connection
 * @node: node containing graphics description
 * @buf: a buffer for the result S-Expr
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the graphics part of the XML description and add it to the S-Expr
 * in buf.  This is a temporary interface as the S-Expr interface will be
 * replaced by XML-RPC in the future. However the XML format should stay
 * valid over time.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
virDomainParseXMLGraphicsDescImage(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   xmlNodePtr node, virBufferPtr buf,
                                   int xendConfigVersion)
{
    xmlChar *graphics_type = NULL;

    graphics_type = xmlGetProp(node, BAD_CAST "type");
    if (graphics_type != NULL) {
        if (xmlStrEqual(graphics_type, BAD_CAST "sdl")) {
            virBufferAddLit(buf, "(sdl 1)");
            /* TODO:
             * Need to understand sdl options
             *
             *virBufferAddLit(buf, "(display localhost:10.0)");
             *virBufferAddLit(buf, "(xauthority /root/.Xauthority)");
             */
        } else if (xmlStrEqual(graphics_type, BAD_CAST "vnc")) {
            virBufferAddLit(buf, "(vnc 1)");
            if (xendConfigVersion >= 2) {
                xmlChar *vncport = xmlGetProp(node, BAD_CAST "port");
                xmlChar *vnclisten = xmlGetProp(node, BAD_CAST "listen");
                xmlChar *vncpasswd = xmlGetProp(node, BAD_CAST "passwd");
                xmlChar *keymap = xmlGetProp(node, BAD_CAST "keymap");

                if (vncport != NULL) {
                    long port = strtol((const char *) vncport, NULL, 10);

                    if (port == -1)
                        virBufferAddLit(buf, "(vncunused 1)");
                    else if (port >= 5900)
                        virBufferVSprintf(buf, "(vncdisplay %ld)",
                                          port - 5900);
                    xmlFree(vncport);
                }
                if (vnclisten != NULL) {
                    virBufferVSprintf(buf, "(vnclisten %s)", vnclisten);
                    xmlFree(vnclisten);
                }
                if (vncpasswd != NULL) {
                    virBufferVSprintf(buf, "(vncpasswd %s)", vncpasswd);
                    xmlFree(vncpasswd);
                }
                if (keymap != NULL) {
                    virBufferVSprintf(buf, "(keymap %s)", keymap);
                    xmlFree(keymap);
                }
            }
        }
        xmlFree(graphics_type);
    }
    return 0;
}


/**
 * virtDomainParseXMLGraphicsDescVFB:
 * @conn: pointer to the hypervisor connection
 * @node: node containing graphics description
 * @buf: a buffer for the result S-Expr
 *
 * Parse the graphics part of the XML description and add it to the S-Expr
 * in buf.  This is a temporary interface as the S-Expr interface will be
 * replaced by XML-RPC in the future. However the XML format should stay
 * valid over time.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
virDomainParseXMLGraphicsDescVFB(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 xmlNodePtr node, virBufferPtr buf)
{
    xmlChar *graphics_type = NULL;

    graphics_type = xmlGetProp(node, BAD_CAST "type");
    if (graphics_type != NULL) {
        virBufferAddLit(buf, "(device (vkbd))");
        virBufferAddLit(buf, "(device (vfb ");
        if (xmlStrEqual(graphics_type, BAD_CAST "sdl")) {
            virBufferAddLit(buf, "(type sdl)");
            /* TODO:
             * Need to understand sdl options
             *
             *virBufferAddLit(buf, "(display localhost:10.0)");
             *virBufferAddLit(buf, "(xauthority /root/.Xauthority)");
             */
        } else if (xmlStrEqual(graphics_type, BAD_CAST "vnc")) {
            virBufferAddLit(buf, "(type vnc)");
            xmlChar *vncport = xmlGetProp(node, BAD_CAST "port");
            xmlChar *vnclisten = xmlGetProp(node, BAD_CAST "listen");
            xmlChar *vncpasswd = xmlGetProp(node, BAD_CAST "passwd");
            xmlChar *keymap = xmlGetProp(node, BAD_CAST "keymap");

            if (vncport != NULL) {
                long port = strtol((const char *) vncport, NULL, 10);

                if (port == -1)
                    virBufferAddLit(buf, "(vncunused 1)");
                else if (port >= 5900)
                    virBufferVSprintf(buf, "(vncdisplay %ld)",
                                      port - 5900);
                xmlFree(vncport);
            }
            if (vnclisten != NULL) {
                virBufferVSprintf(buf, "(vnclisten %s)", vnclisten);
                xmlFree(vnclisten);
            }
            if (vncpasswd != NULL) {
                virBufferVSprintf(buf, "(vncpasswd %s)", vncpasswd);
                xmlFree(vncpasswd);
            }
            if (keymap != NULL) {
                virBufferVSprintf(buf, "(keymap %s)", keymap);
                xmlFree(keymap);
            }
        }
        virBufferAddLit(buf, "))");
        xmlFree(graphics_type);
    }
    return 0;
}


/**
 * virDomainParseXMLOSDescHVM:
 * @conn: pointer to the hypervisor connection
 * @node: node containing HVM OS description
 * @buf: a buffer for the result S-Expr
 * @ctxt: a path context representing the XML description
 * @vcpus: number of virtual CPUs to configure
 * @xendConfigVersion: xend configuration file format
 * @hasKernel: whether the domain is booting from a kernel
 *
 * Parse the OS part of the XML description for a HVM domain
 * and add it to the S-Expr in buf.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLOSDescHVM(virConnectPtr conn, xmlNodePtr node,
                           virBufferPtr buf, xmlXPathContextPtr ctxt,
                           int vcpus, int xendConfigVersion,
                           int hasKernel)
{
    xmlNodePtr cur, txt;
    xmlNodePtr *nodes = NULL;
    xmlChar *loader = NULL;
    char bootorder[5];
    int nbootorder = 0;
    int res, nb_nodes;
    char *str;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((loader == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "loader"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    loader = txt->content;
            } else if ((xmlStrEqual(cur->name, BAD_CAST "boot"))) {
                xmlChar *boot_dev = xmlGetProp(cur, BAD_CAST "dev");

                if (nbootorder ==
                    ((sizeof(bootorder) / sizeof(bootorder[0])) - 1)) {
                    virXMLError(conn, VIR_ERR_XML_ERROR,
                                _("too many boot devices"), 0);
                    return (-1);
                }
                if (xmlStrEqual(boot_dev, BAD_CAST "fd")) {
                    bootorder[nbootorder++] = 'a';
                } else if (xmlStrEqual(boot_dev, BAD_CAST "cdrom")) {
                    bootorder[nbootorder++] = 'd';
                } else if (xmlStrEqual(boot_dev, BAD_CAST "network")) {
                    bootorder[nbootorder++] = 'n';
                } else if (xmlStrEqual(boot_dev, BAD_CAST "hd")) {
                    bootorder[nbootorder++] = 'c';
                } else {
                    xmlFree(boot_dev);
                    /* Any other type of boot dev is unsupported right now */
                    virXMLError(conn, VIR_ERR_XML_ERROR, NULL, 0);
                    return (-1);
                }
                xmlFree(boot_dev);
            }
        }
        cur = cur->next;
    }
    /*
     * XenD always needs boot order defined for HVM, even if
     * booting off a kernel + initrd, so force to 'c' if nothing
     * else is specified
     */
    if (nbootorder == 0)
        bootorder[nbootorder++] = 'c';
    bootorder[nbootorder] = '\0';

    if (loader == NULL) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR, _("no HVM domain loader"), 0);
        return -1;
    }

    /*
     * Originally XenD abused the 'kernel' parameter for the HVM
     * firmware. New XenD allows HVM guests to boot from a kernel
     * and if this is enabled, the HVM firmware must use the new
     * 'loader' parameter
     */
    if (hasKernel) {
        virBufferVSprintf(buf, "(loader '%s')", (const char *) loader);
    } else {
        virBufferVSprintf(buf, "(kernel '%s')", (const char *) loader);
    }

    virBufferVSprintf(buf, "(vcpus %d)", vcpus);

    if (nbootorder)
        virBufferVSprintf(buf, "(boot %s)", bootorder);

    /* get the 1st floppy device file */
    cur = virXPathNode(
         "/domain/devices/disk[@device='floppy' and target/@dev='fda']/source",
         ctxt);
    if (cur != NULL) {
        xmlChar *fdfile;

        fdfile = xmlGetProp(cur, BAD_CAST "file");
        if (fdfile != NULL) {
            virBufferVSprintf(buf, "(fda '%s')", fdfile);
            free(fdfile);
        }
    }

    /* get the 2nd floppy device file */
    cur = virXPathNode(
         "/domain/devices/disk[@device='floppy' and target/@dev='fdb']/source",
         ctxt);
    if (cur != NULL) {
        xmlChar *fdfile;

        fdfile = xmlGetProp(cur, BAD_CAST "file");
        if (fdfile != NULL) {
            virBufferVSprintf(buf, "(fdb '%s')", fdfile);
            free(fdfile);
        }
    }


    /* get the cdrom device file */
    /* Only XenD <= 3.0.2 wants cdrom config here */
    if (xendConfigVersion == 1) {
        cur = virXPathNode(
	  "/domain/devices/disk[@device='cdrom' and target/@dev='hdc']/source",
             ctxt);
        if (cur != NULL) {
            xmlChar *cdfile;

            cdfile = xmlGetProp(cur, BAD_CAST "file");
            if (cdfile != NULL) {
                virBufferVSprintf(buf, "(cdrom '%s')",
                                  (const char *) cdfile);
                xmlFree(cdfile);
            }
        }
    }

    if (virXPathNode("/domain/features/acpi", ctxt) != NULL)
        virBufferAddLit(buf, "(acpi 1)");
    if (virXPathNode("/domain/features/apic", ctxt) != NULL)
        virBufferAddLit(buf, "(apic 1)");
    if (virXPathNode("/domain/features/pae", ctxt) != NULL)
        virBufferAddLit(buf, "(pae 1)");

    virBufferAddLit(buf, "(usb 1)");
    nb_nodes = virXPathNodeSet("/domain/devices/input", ctxt, &nodes);
    if (nb_nodes > 0) {
        int i;

        for (i = 0; i < nb_nodes; i++) {
            xmlChar *itype = NULL, *bus = NULL;
            int isMouse = 1;

            itype = xmlGetProp(nodes[i], (xmlChar *) "type");

            if (!itype) {
                goto error;
            }
            if (!strcmp((const char *) itype, "tablet"))
                isMouse = 0;
            else if (strcmp((const char *) itype, "mouse")) {
                xmlFree(itype);
                virXMLError(conn, VIR_ERR_XML_ERROR,
                            _("invalid input device"), 0);
                goto error;
            }
            xmlFree(itype);

            bus = xmlGetProp(nodes[i], (xmlChar *) "bus");
            if (!bus) {
                if (!isMouse) {
                    /* Nothing - implicit ps2 */
                } else {
                    virBufferAddLit(buf, "(usbdevice tablet)");
                }
            } else {
                if (!strcmp((const char *) bus, "ps2")) {
                    if (!isMouse) {
                        xmlFree(bus);
                        virXMLError(conn, VIR_ERR_XML_ERROR,
                                    _("invalid input device"), 0);
                        goto error;
                    }
                    /* Nothing - implicit ps2 */
                } else if (!strcmp((const char *) bus, "usb")) {
                    if (isMouse)
                        virBufferAddLit(buf, "(usbdevice mouse)");
                    else
                        virBufferAddLit(buf, "(usbdevice tablet)");
                }
            }
            xmlFree(bus);
        }
        free(nodes);
        nodes = NULL;
    }


    res = virXPathBoolean("count(domain/devices/console) > 0", ctxt);
    if (res < 0) {
        virXMLError(conn, VIR_ERR_XML_ERROR, NULL, 0);
        goto error;
    }
    if (res) {
        virBufferAddLit(buf, "(serial pty)");
    }

    str = virXPathString("string(/domain/clock/@offset)", ctxt);
    if (str != NULL && !strcmp(str, "localtime")) {
        virBufferAddLit(buf, "(localtime 1)");
    }
    free(str);

    return (0);

  error:
    free(nodes);
    return (-1);
}


/**
 * virDomainParseXMLOSDescKernel:
 * @conn: pointer to the hypervisor connection
 * @node: node containing PV OS description
 * @buf: a buffer for the result S-Expr
 *
 * Parse the OS part of the XML description for a domain using a direct
 * kernel and initrd to boot.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLOSDescKernel(virConnectPtr conn ATTRIBUTE_UNUSED,
                              xmlNodePtr node,
                              virBufferPtr buf)
{
    xmlNodePtr cur, txt;
    const xmlChar *root = NULL;
    const xmlChar *kernel = NULL;
    const xmlChar *initrd = NULL;
    const xmlChar *cmdline = NULL;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((kernel == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "kernel"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    kernel = txt->content;
            } else if ((root == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "root"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    root = txt->content;
            } else if ((initrd == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "initrd"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    initrd = txt->content;
            } else if ((cmdline == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "cmdline"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    cmdline = txt->content;
            }
        }
        cur = cur->next;
    }

    virBufferVSprintf(buf, "(kernel '%s')", (const char *) kernel);

    if (initrd != NULL)
        virBufferVSprintf(buf, "(ramdisk '%s')", (const char *) initrd);
    if (root != NULL)
        virBufferVSprintf(buf, "(root '%s')", (const char *) root);
    if (cmdline != NULL)
        virBufferVSprintf(buf, "(args '%s')", (const char *) cmdline);

    return (0);
}

/**
 * virCatchXMLParseError:
 * @ctx: the context
 * @msg: the error message
 * @...: extra arguments
 *
 * SAX callback on parsing errors, act as a gate for libvirt own
 * error reporting.
 */
static void
virCatchXMLParseError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if ((ctxt != NULL) &&
        (ctxt->lastError.level == XML_ERR_FATAL) &&
        (ctxt->lastError.message != NULL)) {
        virXMLError(NULL, VIR_ERR_XML_DETAIL, ctxt->lastError.message,
                    ctxt->lastError.line);
    }
}

/**
 * virDomainParseXMLDiskDesc:
 * @node: node containing disk description
 * @conn: pointer to the hypervisor connection
 * @buf: a buffer for the result S-Expr
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the one disk in the XML description and add it to the S-Expr in buf
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLDiskDesc(virConnectPtr conn, xmlNodePtr node,
                          virBufferPtr buf, int hvm, int xendConfigVersion)
{
    xmlNodePtr cur;
    xmlChar *type = NULL;
    xmlChar *device = NULL;
    xmlChar *source = NULL;
    xmlChar *target = NULL;
    xmlChar *drvName = NULL;
    xmlChar *drvType = NULL;
    int ro = 0;
    int shareable = 0;
    int typ = 0;
    int cdrom = 0;
    int isNoSrcCdrom = 0;
    int ret = 0;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "file"))
            typ = 0;
        else if (xmlStrEqual(type, BAD_CAST "block"))
            typ = 1;
        xmlFree(type);
    }
    device = xmlGetProp(node, BAD_CAST "device");

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {

                if (typ == 0)
                    source = xmlGetProp(cur, BAD_CAST "file");
                else
                    source = xmlGetProp(cur, BAD_CAST "dev");
            } else if ((target == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "target"))) {
                target = xmlGetProp(cur, BAD_CAST "dev");
            } else if ((drvName == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "driver"))) {
                drvName = xmlGetProp(cur, BAD_CAST "name");
                if (drvName && !strcmp((const char *) drvName, "tap"))
                    drvType = xmlGetProp(cur, BAD_CAST "type");
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                ro = 1;
            } else if (xmlStrEqual(cur->name, BAD_CAST "shareable")) {
                shareable = 1;
            }
        }
        cur = cur->next;
    }

    if (source == NULL) {
        /* There is a case without the source
         * to the CD-ROM device
         */
        if (hvm && device && !strcmp((const char *) device, "cdrom")) {
            isNoSrcCdrom = 1;
        }
        if (!isNoSrcCdrom) {
            virXMLError(conn, VIR_ERR_NO_SOURCE, (const char *) target, 0);
            ret = -1;
            goto cleanup;
        }
    }
    if (target == NULL) {
        virXMLError(conn, VIR_ERR_NO_TARGET, (const char *) source, 0);
        ret = -1;
        goto cleanup;
    }

    /* Xend (all versions) put the floppy device config
     * under the hvm (image (os)) block
     */
    if (hvm && device && !strcmp((const char *) device, "floppy")) {
        goto cleanup;
    }

    /* Xend <= 3.0.2 doesn't include cdrom config here */
    if (hvm && device && !strcmp((const char *) device, "cdrom")) {
        if (xendConfigVersion == 1)
            goto cleanup;
        else
            cdrom = 1;
    }


    virBufferAddLit(buf, "(device ");
    /* Normally disks are in a (device (vbd ...)) block
     * but blktap disks ended up in a differently named
     * (device (tap ....)) block.... */
    if (drvName && !strcmp((const char *) drvName, "tap")) {
        virBufferAddLit(buf, "(tap ");
    } else {
        virBufferAddLit(buf, "(vbd ");
    }

    if (hvm) {
        char *tmp = (char *) target;

        /* Just in case user mistakenly still puts ioemu: in their XML */
        if (!strncmp((const char *) tmp, "ioemu:", 6))
            tmp += 6;

        /* Xend <= 3.0.2 wants a ioemu: prefix on devices for HVM */
        if (xendConfigVersion == 1)
            virBufferVSprintf(buf, "(dev 'ioemu:%s')", (const char *) tmp);
        else                    /* But newer does not */
            virBufferVSprintf(buf, "(dev '%s%s')", (const char *) tmp,
                              cdrom ? ":cdrom" : ":disk");
    } else
        virBufferVSprintf(buf, "(dev '%s')", (const char *) target);

    if (drvName && !isNoSrcCdrom) {
        if (!strcmp((const char *) drvName, "tap")) {
            virBufferVSprintf(buf, "(uname '%s:%s:%s')",
                              (const char *) drvName,
                              (drvType ? (const char *) drvType : "aio"),
                              (const char *) source);
        } else {
            virBufferVSprintf(buf, "(uname '%s:%s')",
                              (const char *) drvName,
                              (const char *) source);
        }
    } else if (!isNoSrcCdrom) {
        if (typ == 0)
            virBufferVSprintf(buf, "(uname 'file:%s')", source);
        else if (typ == 1) {
            if (source[0] == '/')
                virBufferVSprintf(buf, "(uname 'phy:%s')", source);
            else
                virBufferVSprintf(buf, "(uname 'phy:/dev/%s')", source);
        }
    }
    if (ro == 1)
        virBufferAddLit(buf, "(mode 'r')");
    else if (shareable == 1)
        virBufferAddLit(buf, "(mode 'w!')");
    else
        virBufferAddLit(buf, "(mode 'w')");

    virBufferAddLit(buf, ")");
    virBufferAddLit(buf, ")");

  cleanup:
    if (drvType)
        xmlFree(drvType);
    if (drvName)
        xmlFree(drvName);
    if (device)
        xmlFree(device);
    if (target)
        xmlFree(target);
    if (source)
        xmlFree(source);
    return (ret);
}

/**
 * virDomainParseXMLIfDesc:
 * @conn: pointer to the hypervisor connection
 * @node: node containing the interface description
 * @buf: a buffer for the result S-Expr
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the one interface the XML description and add it to the S-Expr in buf
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLIfDesc(virConnectPtr conn ATTRIBUTE_UNUSED,
                        xmlNodePtr node, virBufferPtr buf, int hvm,
                        int xendConfigVersion)
{
    xmlNodePtr cur;
    xmlChar *type = NULL;
    xmlChar *source = NULL;
    xmlChar *mac = NULL;
    xmlChar *script = NULL;
    xmlChar *ip = NULL;
    int typ = 0;
    int ret = -1;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "bridge"))
            typ = 0;
        else if (xmlStrEqual(type, BAD_CAST "ethernet"))
            typ = 1;
        else if (xmlStrEqual(type, BAD_CAST "network"))
            typ = 2;
        xmlFree(type);
    }
    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                if (typ == 0)
                    source = xmlGetProp(cur, BAD_CAST "bridge");
                else if (typ == 1)
                    source = xmlGetProp(cur, BAD_CAST "dev");
                else
                    source = xmlGetProp(cur, BAD_CAST "network");
            } else if ((mac == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "mac"))) {
                mac = xmlGetProp(cur, BAD_CAST "address");
            } else if ((script == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "script"))) {
                script = xmlGetProp(cur, BAD_CAST "path");
            } else if ((ip == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "ip"))) {
                /* XXX in future expect to need to have > 1 ip
                 * address element - eg ipv4 & ipv6. For now
                 * xen only supports a single address though
                 * so lets ignore that complication */
                ip = xmlGetProp(cur, BAD_CAST "address");
            }
        }
        cur = cur->next;
    }

    virBufferAddLit(buf, "(vif ");
    if (mac != NULL) {
        unsigned char addr[6];
        if (virParseMacAddr((const char*) mac, addr) == -1) {
            virXMLError(conn, VIR_ERR_INVALID_MAC, (const char *) mac, 0);
            goto error;
        }
        virBufferVSprintf(buf, "(mac '%s')", (const char *) mac);
    }
    if (source != NULL) {
        if (typ == 0)
            virBufferVSprintf(buf, "(bridge '%s')", (const char *) source);
        else if (typ == 1)      /* TODO does that work like that ? */
            virBufferVSprintf(buf, "(dev '%s')", (const char *) source);
        else {
            virNetworkPtr network =
                virNetworkLookupByName(conn, (const char *) source);
            char *bridge;

            if (!network || !(bridge = virNetworkGetBridgeName(network))) {
                if (network)
                    virNetworkFree(network);
                virXMLError(conn, VIR_ERR_NO_SOURCE, (const char *) source,
                            0);
                goto error;
            }
            virNetworkFree(network);
            virBufferVSprintf(buf, "(bridge '%s')", bridge);
            free(bridge);
        }
    }
    if (script != NULL)
        virBufferVSprintf(buf, "(script '%s')", script);
    if (ip != NULL)
        virBufferVSprintf(buf, "(ip '%s')", ip);
    /*
     * apparently (type ioemu) breaks paravirt drivers on HVM so skip this
     * from Xen 3.1.0
     */
    if ((hvm) && (xendConfigVersion < 4))
        virBufferAddLit(buf, "(type ioemu)");

    virBufferAddLit(buf, ")");
    ret = 0;
  error:
    if (mac != NULL)
        xmlFree(mac);
    if (source != NULL)
        xmlFree(source);
    if (script != NULL)
        xmlFree(script);
    if (ip != NULL)
        xmlFree(ip);
    return (ret);
}

/**
 * virDomainParseXMLDesc:
 * @conn: pointer to the hypervisor connection
 * @xmldesc: string with the XML description
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the XML description and turn it into the xend sexp needed to
 * create the domain. This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns the 0 terminatedi S-Expr string or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainParseXMLDesc(virConnectPtr conn, const char *xmldesc, char **name,
                      int xendConfigVersion)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node;
    char *nam = NULL;
    virBuffer buf;
    xmlChar *prop;
    xmlParserCtxtPtr pctxt;
    xmlXPathContextPtr ctxt = NULL;
    int i, res;
    int bootloader = 0;
    int hvm = 0;
    unsigned int vcpus = 1;
    unsigned long mem = 0, max_mem = 0;
    char *str;
    double f;
    xmlNodePtr *nodes;
    int nb_nodes;

    if (name != NULL)
        *name = NULL;
    buf.content = malloc(1000);
    if (buf.content == NULL)
        return (NULL);
    buf.size = 1000;
    buf.use = 0;

    pctxt = xmlNewParserCtxt();
    if ((pctxt == NULL) || (pctxt->sax == NULL)) {
        goto error;
    }

    /* TODO pass the connection point to the error handler:
     *   pctxt->userData = virConnectPtr;
     */
    pctxt->sax->error = virCatchXMLParseError;

    xml = xmlCtxtReadDoc(pctxt, (const xmlChar *) xmldesc, "domain.xml",
                         NULL, XML_PARSE_NOENT | XML_PARSE_NONET |
                         XML_PARSE_NOWARNING);
    if (xml == NULL) {
        goto error;
    }
    node = xmlDocGetRootElement(xml);
    if ((node == NULL) || (!xmlStrEqual(node->name, BAD_CAST "domain")))
        goto error;

    prop = xmlGetProp(node, BAD_CAST "type");
    if (prop != NULL) {
        if (!xmlStrEqual(prop, BAD_CAST "xen")) {
            xmlFree(prop);
            goto error;
        }
        xmlFree(prop);
    }
    virBufferAddLit(&buf, "(vm ");
    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        goto error;
    }
    /*
     * extract some of the basics, name, memory, cpus ...
     */
    nam = virXPathString("string(/domain/name[1])", ctxt);
    if (nam == NULL) {
        virXMLError(conn, VIR_ERR_NO_NAME, xmldesc, 0);
        goto error;
    }
    virBufferVSprintf(&buf, "(name '%s')", nam);

    if ((virXPathNumber("number(/domain/memory[1])", ctxt, &f) < 0) ||
        (f < MIN_XEN_GUEST_SIZE * 1024)) {
        max_mem = 128;
    } else {
        max_mem = (f / 1024);
    }

    if ((virXPathNumber("number(/domain/currentMemory[1])", ctxt, &f) < 0)
        || (f < MIN_XEN_GUEST_SIZE * 1024)) {
        mem = max_mem;
    } else {
        mem = (f / 1024);
        if (mem > max_mem) {
            max_mem = mem;
        }
    }
    virBufferVSprintf(&buf, "(memory %lu)(maxmem %lu)", mem, max_mem);

    if ((virXPathNumber("number(/domain/vcpu[1])", ctxt, &f) == 0) &&
        (f > 0)) {
        vcpus = (unsigned int) f;
    }
    virBufferVSprintf(&buf, "(vcpus %u)", vcpus);

    str = virXPathString("string(/domain/vcpu/@cpuset)", ctxt);
    if (str != NULL) {
        int maxcpu = xenNbCpus(conn);
        char *cpuset = NULL;
        char *ranges = NULL;
        const char *cur = str;

        /*
         * Parse the CPUset attribute given in libvirt format and reserialize
         * it in a range format guaranteed to be understood by Xen.
         */
        if (maxcpu > 0) {
            cpuset = malloc(maxcpu * sizeof(*cpuset));
            if (cpuset != NULL) {
                res = virParseCpuSet(conn, &cur, 0, cpuset, maxcpu);
                if (res > 0) {
                    ranges = virSaveCpuSet(conn, cpuset, maxcpu);
                    if (ranges != NULL) {
                        virBufferVSprintf(&buf, "(cpus '%s')", ranges);
                        free(ranges);
                    }
                }
                free(cpuset);
                if (res < 0)
                    goto error;
            } else {
                virXMLError(conn, VIR_ERR_NO_MEMORY, xmldesc, 0);
            }
        }
        free(str);
    }

    str = virXPathString("string(/domain/uuid[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(uuid '%s')", str);
        free(str);
    }

    str = virXPathString("string(/domain/bootloader[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(bootloader '%s')", str);
        /*
         * if using a bootloader, the kernel and initrd strings are not
         * significant and should be discarded
         */
        bootloader = 1;
        free(str);
    } else if (virXPathNumber("count(/domain/bootloader)", ctxt, &f) == 0
               && (f > 0)) {
        virBufferAddLit(&buf, "(bootloader)");
        /*
         * if using a bootloader, the kernel and initrd strings are not
         * significant and should be discarded
         */
        bootloader = 1;
    }

    str = virXPathString("string(/domain/bootloader_args[1])", ctxt);
    if (str != NULL && bootloader) {
        /*
         * ignore the bootloader_args value unless a bootloader was specified
         */
        virBufferVSprintf(&buf, "(bootloader_args '%s')", str);
        free(str);
    }

    str = virXPathString("string(/domain/on_poweroff[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(on_poweroff '%s')", str);
        free(str);
    }

    str = virXPathString("string(/domain/on_reboot[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(on_reboot '%s')", str);
        free(str);
    }

    str = virXPathString("string(/domain/on_crash[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(on_crash '%s')", str);
        free(str);
    }

    if (!bootloader) {
        if ((node = virXPathNode("/domain/os[1]", ctxt)) != NULL) {
            int has_kernel = 0;

            /* Analyze of the os description, based on HVM or PV. */
            str = virXPathString("string(/domain/os/type[1])", ctxt);
            if ((str != NULL) && STREQ(str, "hvm"))
                hvm = 1;
            xmlFree(str);
            str = NULL;

            if (hvm)
                virBufferAddLit(&buf, "(image (hvm ");
            else
                virBufferAddLit(&buf, "(image (linux ");

            if (virXPathBoolean("count(/domain/os/kernel) > 0", ctxt)) {
                if (virDomainParseXMLOSDescKernel(conn, node,
                                                  &buf) != 0)
                    goto error;
                has_kernel = 1;
            }

            if (hvm &&
                virDomainParseXMLOSDescHVM(conn, node,
                                           &buf, ctxt, vcpus,
                                           xendConfigVersion,
                                           has_kernel) != 0)
                goto error;

            /* get the device emulation model */
            str = virXPathString("string(/domain/devices/emulator[1])", ctxt);
            if (str != NULL) {
                virBufferVSprintf(&buf, "(device_model '%s')", str);
                xmlFree(str);
                str = NULL;
            }

            /* PV graphics for xen <= 3.0.4, or HVM graphics for xen <= 3.1.0 */
            if ((!hvm && xendConfigVersion < 3) ||
                (hvm && xendConfigVersion < 4)) {
                xmlNodePtr cur;
                cur = virXPathNode("/domain/devices/graphics[1]", ctxt);
                if (cur != NULL &&
                    virDomainParseXMLGraphicsDescImage(conn, cur, &buf,
                                                       xendConfigVersion) != 0)
                    goto error;
            }

            virBufferAddLit(&buf, "))");
        } else {
            virXMLError(conn, VIR_ERR_NO_OS, nam, 0);
            goto error;
        }
    }

    /* analyze of the devices */
    nb_nodes = virXPathNodeSet("/domain/devices/disk", ctxt, &nodes);
    if (nb_nodes > 0) {
        for (i = 0; i < nb_nodes; i++) {
            res = virDomainParseXMLDiskDesc(conn, nodes[i], &buf,
                                            hvm, xendConfigVersion);
            if (res != 0) {
                free(nodes);
                goto error;
            }
        }
        free(nodes);
    }

    nb_nodes = virXPathNodeSet("/domain/devices/interface", ctxt, &nodes);
    if (nb_nodes > 0) {
        for (i = 0; i < nb_nodes; i++) {
            virBufferAddLit(&buf, "(device ");
            res =
                virDomainParseXMLIfDesc(conn, nodes[i], &buf, hvm,
                                        xendConfigVersion);
            if (res != 0) {
                free(nodes);
                goto error;
            }
            virBufferAddLit(&buf, ")");
        }
        free(nodes);
    }

    /* New style PV graphics config xen >= 3.0.4,
     * or HVM graphics config xen >= 3.0.5 */
    if ((xendConfigVersion >= 3 && !hvm) ||
        (xendConfigVersion >= 4 && hvm)) {
        nb_nodes = virXPathNodeSet("/domain/devices/graphics", ctxt, &nodes);
        if (nb_nodes > 0) {
            for (i = 0; i < nb_nodes; i++) {
                res = virDomainParseXMLGraphicsDescVFB(conn, nodes[i], &buf);
                if (res != 0) {
                    free(nodes);
                    goto error;
                }
            }
            free(nodes);
        }
    }


    virBufferAddLit(&buf, ")"); /* closes (vm */
    buf.content[buf.use] = 0;

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlFreeParserCtxt(pctxt);

    if (name != NULL)
        *name = nam;
    else
        free(nam);

    return (buf.content);

  error:
    free(nam);
    if (name != NULL)
        *name = NULL;
    xmlXPathFreeContext(ctxt);
    if (xml != NULL)
        xmlFreeDoc(xml);
    if (pctxt != NULL)
        xmlFreeParserCtxt(pctxt);
    free(buf.content);
    return (NULL);
}

/**
 * virParseXMLDevice:
 * @conn: pointer to the hypervisor connection
 * @xmldesc: string with the XML description
 * @hvm: 1 for fully virtualized guest, 0 for paravirtualized
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the XML description and turn it into the xend sexp needed to
 * create the device. This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns the 0-terminated S-Expr string, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virParseXMLDevice(virConnectPtr conn, const char *xmldesc, int hvm,
                  int xendConfigVersion)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node;
    virBuffer buf;

    buf.content = malloc(1000);
    if (buf.content == NULL)
        return (NULL);
    buf.size = 1000;
    buf.use = 0;
    buf.content[0] = 0;
    xml = xmlReadDoc((const xmlChar *) xmldesc, "device.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (xml == NULL) {
        virXMLError(conn, VIR_ERR_XML_ERROR, NULL, 0);
        goto error;
    }
    node = xmlDocGetRootElement(xml);
    if (node == NULL)
        goto error;
    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        if (virDomainParseXMLDiskDesc(conn, node, &buf, hvm,
	                              xendConfigVersion) != 0)
            goto error;
        /* SXP is not created when device is "floppy". */
        else if (buf.use == 0)
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        if (virDomainParseXMLIfDesc(conn, node, &buf, hvm,
	                            xendConfigVersion) != 0)
            goto error;
    } else {
        virXMLError(conn, VIR_ERR_XML_ERROR, (const char *) node->name, 0);
        goto error;
    }
  cleanup:
    if (xml != NULL)
        xmlFreeDoc(xml);
    return buf.content;
  error:
    free(buf.content);
    buf.content = NULL;
    goto cleanup;
}


/**
 * virDomainXMLDevID:
 * @domain: pointer to domain object
 * @xmldesc: string with the XML description
 * @class: Xen device class "vbd" or "vif" (OUT)
 * @ref: Xen device reference (OUT)
 *
 * Set class according to XML root, and:
 *  - if disk, copy in ref the target name from description
 *  - if network, get MAC address from description, scan XenStore and
 *    copy in ref the corresponding vif number.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainXMLDevID(virDomainPtr domain, const char *xmldesc, char *class,
                  char *ref, int ref_len)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node, cur;
    xmlChar *attr = NULL;

    char *xref;
    int ret = 0;

    xml = xmlReadDoc((const xmlChar *) xmldesc, "device.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (xml == NULL) {
        virXMLError(NULL, VIR_ERR_XML_ERROR, NULL, 0);
        goto error;
    }
    node = xmlDocGetRootElement(xml);
    if (node == NULL)
        goto error;
    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        strcpy(class, "vbd");
        for (cur = node->children; cur != NULL; cur = cur->next) {
            if ((cur->type != XML_ELEMENT_NODE) ||
                (!xmlStrEqual(cur->name, BAD_CAST "target")))
                continue;
            attr = xmlGetProp(cur, BAD_CAST "dev");
            if (attr == NULL)
                goto error;
            xref = xenStoreDomainGetDiskID(domain->conn, domain->id,
                                              (char *) attr);
            if (xref != NULL) {
                strncpy(ref, xref, ref_len);
                free(xref);
                ref[ref_len - 1] = '\0';
                goto cleanup;
            }
            /* hack to avoid the warning that domain is unused */
            if (domain->id < 0)
                ret = -1;

            goto error;
        }
    } else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        strcpy(class, "vif");
        for (cur = node->children; cur != NULL; cur = cur->next) {
            if ((cur->type != XML_ELEMENT_NODE) ||
                (!xmlStrEqual(cur->name, BAD_CAST "mac")))
                continue;
            attr = xmlGetProp(cur, BAD_CAST "address");
            if (attr == NULL)
                goto error;

            xref = xenStoreDomainGetNetworkID(domain->conn, domain->id,
                                              (char *) attr);
            if (xref != NULL) {
                strncpy(ref, xref, ref_len);
                free(xref);
                ref[ref_len - 1] = '\0';
                goto cleanup;
            }
            /* hack to avoid the warning that domain is unused */
            if (domain->id < 0)
                ret = -1;

            goto error;
        }
    } else {
        virXMLError(NULL, VIR_ERR_XML_ERROR, (const char *) node->name, 0);
    }
  error:
    ret = -1;
  cleanup:
    if (xml != NULL)
        xmlFreeDoc(xml);
    if (attr != NULL)
        xmlFree(attr);
    return ret;
}
#endif /* WITH_XEN */
#endif /* !PROXY */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
