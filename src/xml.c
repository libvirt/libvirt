/*
 * xml.c: XML based interfaces for the libvir library
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvirt/libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef WITH_XEN
#include <xs.h>
#endif
#include <math.h> /* for isnan() */
#include "internal.h"
#include "hash.h"
#include "sexpr.h"
#include "xml.h"
#include "xs_internal.h" /* for xenStoreDomainGetNetworkID */

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
virXMLError(virConnectPtr conn, virErrorNumber error, const char *info, int value)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_XML, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}

#ifndef PROXY
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
virXPathString(const char *xpath, xmlXPathContextPtr ctxt) {
    xmlXPathObjectPtr obj;
    char *ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathString()", 0);
        return(NULL);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0))
        return(NULL);
    ret = strdup((char *) obj->stringval);
    xmlXPathFreeObject(obj);
    if (ret == NULL) {
        virXMLError(NULL, VIR_ERR_NO_MEMORY, "strdup", 0);
    }
    return(ret);
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
virXPathNumber(const char *xpath, xmlXPathContextPtr ctxt, double *value) {
    xmlXPathObjectPtr obj;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathNumber()", 0);
        return(-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval))) {
	xmlXPathFreeObject(obj);
	return(-1);
    }
    
    *value = obj->floatval;
    xmlXPathFreeObject(obj);
    return(0);
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
virXPathLong(const char *xpath, xmlXPathContextPtr ctxt, long *value) {
    xmlXPathObjectPtr obj;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathNumber()", 0);
        return(-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        char *conv = NULL;
	long val;

        val = strtol((const char*)obj->stringval, &conv, 10);
        if (conv == (const char*)obj->stringval) {
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
    return(ret);
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
virXPathBoolean(const char *xpath, xmlXPathContextPtr ctxt) {
    xmlXPathObjectPtr obj;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathBoolean()", 0);
        return(-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN) ||
        (obj->boolval < 0) || (obj->boolval > 1)) {
	xmlXPathFreeObject(obj);
	return(-1);
    }
    ret = obj->boolval;
    
    xmlXPathFreeObject(obj);
    return(ret);
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
virXPathNode(const char *xpath, xmlXPathContextPtr ctxt) {
    xmlXPathObjectPtr obj;
    xmlNodePtr ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathNode()", 0);
        return(NULL);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
	(obj->nodesetval->nodeTab == NULL)) {
	xmlXPathFreeObject(obj);
	return(NULL);
    }
    
    ret = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    return(ret);
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
virXPathNodeSet(const char *xpath, xmlXPathContextPtr ctxt, xmlNodePtr **list) {
    xmlXPathObjectPtr obj;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR, 
	            "Invalid parameter to virXPathNodeSet()", 0);
        return(-1);
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
	(obj->nodesetval->nodeTab == NULL)) {
	xmlXPathFreeObject(obj);
	if (list != NULL)
	    *list = NULL;
	return(-1);
    }
    
    ret = obj->nodesetval->nodeNr;
    if (list != NULL) {
	*list = malloc(ret * sizeof(xmlNodePtr));
	if (*list == NULL) {
	    virXMLError(NULL, VIR_ERR_NO_MEMORY, 
	                _("allocate string array"), ret * sizeof(xmlNodePtr));
	} else {
	    memcpy(*list, obj->nodesetval->nodeTab, ret * sizeof(xmlNodePtr));
	}
    }
    xmlXPathFreeObject(obj);
    return(ret);
}
#endif /* !PROXY */

/**
 * virBufferGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate on top of existing used space
 *
 * Grow the available space of an XML buffer to at least @len bytes.
 *
 * Returns the new available space or -1 in case of error
 */
static int
virBufferGrow(virBufferPtr buf, unsigned int len)
{
    int size;
    char *newbuf;

    if (buf == NULL)
        return (-1);
    if (len + buf->use < buf->size)
        return (0);

    size = buf->use + len + 1000;

    newbuf = (char *) realloc(buf->content, size);
    if (newbuf == NULL) {
        virXMLError(NULL, VIR_ERR_NO_MEMORY, _("growing buffer"), size);
        return (-1);
    }
    buf->content = newbuf;
    buf->size = size;
    return (buf->size - buf->use);
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
int
virBufferAdd(virBufferPtr buf, const char *str, int len)
{
    unsigned int needSize;

    if ((str == NULL) || (buf == NULL)) {
        return -1;
    }
    if (len == 0)
        return 0;

    if (len < 0)
        len = strlen(str);

    needSize = buf->use + len + 2;
    if (needSize > buf->size) {
        if (!virBufferGrow(buf, needSize - buf->use)) {
            return (-1);
        }
    }
    /* XXX: memmove() is 2x slower than memcpy(), do we really need it? */
    memmove(&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;
    return (0);
}

virBufferPtr
virBufferNew(unsigned int size)
{
    virBufferPtr buf;

    if (!(buf = malloc(sizeof(*buf)))) {
        virXMLError(NULL, VIR_ERR_NO_MEMORY, _("allocate new buffer"), sizeof(*buf));
        return NULL;
    }
    if (size && (buf->content = malloc(size))==NULL) {
        virXMLError(NULL, VIR_ERR_NO_MEMORY, _("allocate buffer content"), size);
        free(buf);
        return NULL;
    }
    buf->size = size;
    buf->use = 0;

    return buf;
}

void
virBufferFree(virBufferPtr buf)
{
    if (buf) {
        if (buf->content)
            free(buf->content);
        free(buf);
    }
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
int
virBufferVSprintf(virBufferPtr buf, const char *format, ...)
{
    int size, count;
    va_list locarg, argptr;

    if ((format == NULL) || (buf == NULL)) {
        return (-1);
    }
    size = buf->size - buf->use - 1;
    va_start(argptr, format);
    va_copy(locarg, argptr);
    while (((count = vsnprintf(&buf->content[buf->use], size, format,
                               locarg)) < 0) || (count >= size - 1)) {
        buf->content[buf->use] = 0;
        va_end(locarg);
        if (virBufferGrow(buf, 1000) < 0) {
            return (-1);
        }
        size = buf->size - buf->use - 1;
        va_copy(locarg, argptr);
    }
    va_end(locarg);
    buf->use += count;
    buf->content[buf->use] = 0;
    return (0);
}

/**
 * virBufferStrcat:
 * @buf:  the buffer to dump
 * @argptr:  the variable list of strings, the last argument must be NULL
 *
 * Concatenate strings to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
virBufferStrcat(virBufferPtr buf, ...)
{
    va_list ap;
    char *str;

    va_start(ap, buf);

    while ((str = va_arg(ap, char *)) != NULL) {
        unsigned int len = strlen(str);
        unsigned int needSize = buf->use + len + 2;

        if (needSize > buf->size) {
            if (!virBufferGrow(buf, needSize - buf->use))
                return -1;
        }
        memcpy(&buf->content[buf->use], str, len);
        buf->use += len;
        buf->content[buf->use] = 0;
    }
    va_end(ap);
    return 0;
}


#ifndef PROXY
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
static int virDomainParseXMLGraphicsDescImage(virConnectPtr conn ATTRIBUTE_UNUSED, xmlNodePtr node, virBufferPtr buf, int xendConfigVersion)
{
    xmlChar *graphics_type = NULL;

    graphics_type = xmlGetProp(node, BAD_CAST "type");
    if (graphics_type != NULL) {
        if (xmlStrEqual(graphics_type, BAD_CAST "sdl")) {
            virBufferAdd(buf, "(sdl 1)", 7);
            /* TODO:
             * Need to understand sdl options
             *
             *virBufferAdd(buf, "(display localhost:10.0)", 24);
             *virBufferAdd(buf, "(xauthority /root/.Xauthority)", 30);
             */
        }
        else if (xmlStrEqual(graphics_type, BAD_CAST "vnc")) {
            virBufferAdd(buf, "(vnc 1)", 7);
            if (xendConfigVersion >= 2) {
                xmlChar *vncport = xmlGetProp(node, BAD_CAST "port");
                xmlChar *vnclisten = xmlGetProp(node, BAD_CAST "listen");
                xmlChar *vncpasswd = xmlGetProp(node, BAD_CAST "passwd");
                xmlChar *keymap = xmlGetProp(node, BAD_CAST "keymap");
                if (vncport != NULL) {
                    long port = strtol((const char *)vncport, NULL, 10);
                    if (port == -1)
                        virBufferAdd(buf, "(vncunused 1)", 13);
                    else if (port >= 5900)
                        virBufferVSprintf(buf, "(vncdisplay %ld)", port - 5900);
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
static int virDomainParseXMLGraphicsDescVFB(virConnectPtr conn ATTRIBUTE_UNUSED, xmlNodePtr node, virBufferPtr buf)
{
    xmlChar *graphics_type = NULL;

    graphics_type = xmlGetProp(node, BAD_CAST "type");
    if (graphics_type != NULL) {
        virBufferAdd(buf, "(device (vkbd))", 15);
        virBufferAdd(buf, "(device (vfb ", 13);
        if (xmlStrEqual(graphics_type, BAD_CAST "sdl")) {
            virBufferAdd(buf, "(type sdl)", 10);
            /* TODO:
             * Need to understand sdl options
             *
             *virBufferAdd(buf, "(display localhost:10.0)", 24);
             *virBufferAdd(buf, "(xauthority /root/.Xauthority)", 30);
             */
        }
        else if (xmlStrEqual(graphics_type, BAD_CAST "vnc")) {
            virBufferAdd(buf, "(type vnc)", 10);
            xmlChar *vncport = xmlGetProp(node, BAD_CAST "port");
            xmlChar *vnclisten = xmlGetProp(node, BAD_CAST "listen");
            xmlChar *vncpasswd = xmlGetProp(node, BAD_CAST "passwd");
            xmlChar *keymap = xmlGetProp(node, BAD_CAST "keymap");
            if (vncport != NULL) {
                long port = strtol((const char *)vncport, NULL, 10);
                if (port == -1)
                    virBufferAdd(buf, "(vncunused 1)", 13);
                else if (port >= 5900)
                    virBufferVSprintf(buf, "(vncdisplay %ld)", port - 5900);
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
        virBufferAdd(buf, "))", 2);
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
 *
 * Parse the OS part of the XML description for an HVM domain and add it to
 * the S-Expr in buf. This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLOSDescHVM(virConnectPtr conn, xmlNodePtr node, virBufferPtr buf, xmlXPathContextPtr ctxt, int vcpus, int xendConfigVersion)
{
    xmlNodePtr cur, txt;
    xmlChar *type = NULL;
    xmlChar *loader = NULL;
    char bootorder[5];
    int nbootorder = 0;
    int res;
    char *str;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((type == NULL)
                && (xmlStrEqual(cur->name, BAD_CAST "type"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    type = txt->content;
            } else if ((loader == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "loader"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    loader = txt->content;
            } else if ((xmlStrEqual(cur->name, BAD_CAST "boot"))) {
                xmlChar *boot_dev = xmlGetProp(cur, BAD_CAST "dev");
                if (nbootorder == ((sizeof(bootorder)/sizeof(bootorder[0]))-1)) {
                    virXMLError(conn, VIR_ERR_XML_ERROR, "too many boot devices", 0);
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
    bootorder[nbootorder] = '\0';
    if ((type == NULL) || (!xmlStrEqual(type, BAD_CAST "hvm"))) {
        /* VIR_ERR_OS_TYPE */
        virXMLError(conn, VIR_ERR_OS_TYPE, (const char *) type, 0);
        return (-1);
    }
    virBufferAdd(buf, "(image (hvm ", 12);
    if (loader == NULL) {
        virXMLError(conn, VIR_ERR_NO_KERNEL, NULL, 0);
        goto error;
    } else {
        virBufferVSprintf(buf, "(kernel '%s')", (const char *) loader);
    }

    /* get the device emulation model */
    str = virXPathString("string(/domain/devices/emulator[1])", ctxt);
    if (str == NULL) {
        virXMLError(conn, VIR_ERR_NO_KERNEL, NULL, 0); /* TODO: error */
        goto error;
    }
    virBufferVSprintf(buf, "(device_model '%s')", str);
    xmlFree(str);

    virBufferVSprintf(buf, "(vcpus %d)", vcpus);

    if (nbootorder)
        virBufferVSprintf(buf, "(boot %s)", bootorder);

    /* get the 1st floppy device file */
	cur = virXPathNode("/domain/devices/disk[@device='floppy' and target/@dev='fda']/source",
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
	cur = virXPathNode("/domain/devices/disk[@device='floppy' and target/@dev='fdb']/source",
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
	    cur = virXPathNode("/domain/devices/disk[@device='cdrom' and target/@dev='hdc']/source",
	                       ctxt);
	    if (cur != NULL) {
            xmlChar *cdfile;

            cdfile = xmlGetProp(cur, BAD_CAST "file");
            if (cdfile != NULL) {
                virBufferVSprintf(buf, "(cdrom '%s')",
                                  (const char *)cdfile);
                xmlFree(cdfile);
            }
        }
    }

    if (virXPathNode("/domain/features/acpi", ctxt) != NULL)
        virBufferAdd(buf, "(acpi 1)", 8);
    if (virXPathNode("/domain/features/apic", ctxt) != NULL)
        virBufferAdd(buf, "(apic 1)", 8);
    if (virXPathNode("/domain/features/pae", ctxt) != NULL)
        virBufferAdd(buf, "(pae 1)", 7);

    res = virXPathBoolean("count(domain/devices/console) > 0", ctxt);
    if (res < 0) {
        virXMLError(conn, VIR_ERR_XML_ERROR, NULL, 0);
        goto error;
    }
    if (res) {
        virBufferAdd(buf, "(serial pty)", 12);
    }

    /* HVM graphics for xen <= 3.0.5 */
    if (xendConfigVersion < 4) {
        /* Is a graphics device specified? */
        cur = virXPathNode("/domain/devices/graphics[1]", ctxt);
        if (cur != NULL) {
            res = virDomainParseXMLGraphicsDescImage(conn, cur, buf,
                                                     xendConfigVersion);
            if (res != 0) {
                goto error;
            }
        }
    }

    virBufferAdd(buf, "))", 2);

    return (0);

 error:
    return(-1);
}

/**
 * virDomainParseXMLOSDescPV:
 * @conn: pointer to the hypervisor connection
 * @node: node containing PV OS description
 * @buf: a buffer for the result S-Expr
 * @ctxt: a path context representing the XML description
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the OS part of the XML description for a paravirtualized domain
 * and add it to the S-Expr in buf.  This is a temporary interface as the
 * S-Expr interface will be replaced by XML-RPC in the future. However
 * the XML format should stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLOSDescPV(virConnectPtr conn, xmlNodePtr node, virBufferPtr buf, xmlXPathContextPtr ctxt, int xendConfigVersion)
{
    xmlNodePtr cur, txt;
    const xmlChar *type = NULL;
    const xmlChar *root = NULL;
    const xmlChar *kernel = NULL;
    const xmlChar *initrd = NULL;
    const xmlChar *cmdline = NULL;
    int res;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((type == NULL)
                && (xmlStrEqual(cur->name, BAD_CAST "type"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
                    (txt->next == NULL))
                    type = txt->content;
            } else if ((kernel == NULL) &&
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
    if ((type != NULL) && (!xmlStrEqual(type, BAD_CAST "linux"))) {
        /* VIR_ERR_OS_TYPE */
        virXMLError(conn, VIR_ERR_OS_TYPE, (const char *) type, 0);
        return (-1);
    }
    virBufferAdd(buf, "(image (linux ", 14);
    if (kernel == NULL) {
        virXMLError(conn, VIR_ERR_NO_KERNEL, NULL, 0);
        return (-1);
    } else {
        virBufferVSprintf(buf, "(kernel '%s')", (const char *) kernel);
    }
    if (initrd != NULL)
        virBufferVSprintf(buf, "(ramdisk '%s')", (const char *) initrd);
    if (root != NULL)
        virBufferVSprintf(buf, "(root '%s')", (const char *) root);
    if (cmdline != NULL)
        virBufferVSprintf(buf, "(args '%s')", (const char *) cmdline);

    /* PV graphics for xen <= 3.0.4 */
    if (xendConfigVersion < 3) {
        cur = virXPathNode("/domain/devices/graphics[1]", ctxt);
        if (cur != NULL) {
            res = virDomainParseXMLGraphicsDescImage(conn, cur, buf,
                                                     xendConfigVersion);
            if (res != 0) {
                goto error;
            }
        }
    }

 error:
    virBufferAdd(buf, "))", 2);
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
virCatchXMLParseError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...) {
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
virDomainParseXMLDiskDesc(virConnectPtr conn, xmlNodePtr node, virBufferPtr buf, int hvm, int xendConfigVersion)
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
                if (drvName && !strcmp((const char *)drvName, "tap"))
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
        if (hvm &&
            device &&
            !strcmp((const char *)device, "cdrom")) {
            isNoSrcCdrom = 1;
        }
        if (!isNoSrcCdrom) {
            virXMLError(conn, VIR_ERR_NO_SOURCE, (const char *) target, 0);

            if (target != NULL)
                xmlFree(target);
            if (device != NULL)
                xmlFree(device);
            return (-1);
        }
    }
    if (target == NULL) {
        virXMLError(conn, VIR_ERR_NO_TARGET, (const char *) source, 0);
        if (source != NULL)
            xmlFree(source);
        if (device != NULL)
            xmlFree(device);
        return (-1);
    }

    /* Xend (all versions) put the floppy device config
     * under the hvm (image (os)) block
     */
    if (hvm &&
        device &&
        !strcmp((const char *)device, "floppy")) {
        goto cleanup;
    }

    /* Xend <= 3.0.2 doesn't include cdrom config here */
    if (hvm &&
        device &&
        !strcmp((const char *)device, "cdrom")) {
        if (xendConfigVersion == 1)
            goto cleanup;
        else
            cdrom = 1;
    }


    virBufferAdd(buf, "(device ", 8);
    /* Normally disks are in a (device (vbd ...)) block
       but blktap disks ended up in a differently named
       (device (tap ....)) block.... */
    if (drvName && !strcmp((const char *)drvName, "tap")) {
        virBufferAdd(buf, "(tap ", 5);
    } else {
        virBufferAdd(buf, "(vbd ", 5);
    }

    if (hvm) {
        char *tmp = (char *)target;
        /* Just in case user mistakenly still puts ioemu: in their XML */
        if (!strncmp((const char *) tmp, "ioemu:", 6))
            tmp += 6;

        /* Xend <= 3.0.2 wants a ioemu: prefix on devices for HVM */
        if (xendConfigVersion == 1)
            virBufferVSprintf(buf, "(dev 'ioemu:%s')", (const char *)tmp);
        else /* But newer does not */
            virBufferVSprintf(buf, "(dev '%s%s')", (const char *)tmp, cdrom ? ":cdrom" : ":disk");
    } else
        virBufferVSprintf(buf, "(dev '%s')", (const char *)target);

    if (drvName && !isNoSrcCdrom) {
        if (!strcmp((const char *)drvName, "tap")) {
            virBufferVSprintf(buf, "(uname '%s:%s:%s')",
                              (const char *)drvName,
                              (drvType ? (const char *)drvType : "aio"),
                              (const char *)source);
        } else {
            virBufferVSprintf(buf, "(uname '%s:%s')",
                              (const char *)drvName,
                              (const char *)source);
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
        virBufferVSprintf(buf, "(mode 'r')");
    else if (shareable == 1)
        virBufferVSprintf(buf, "(mode 'w!')");
    else
        virBufferVSprintf(buf, "(mode 'w')");

    virBufferAdd(buf, ")", 1);
    virBufferAdd(buf, ")", 1);

 cleanup:
    xmlFree(drvType);
    xmlFree(drvName);
    xmlFree(device);
    xmlFree(target);
    xmlFree(source);
    return (0);
}

/**
 * virDomainParseXMLIfDesc:
 * @conn: pointer to the hypervisor connection
 * @node: node containing the interface description
 * @buf: a buffer for the result S-Expr
 *
 * Parse the one interface the XML description and add it to the S-Expr in buf
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virDomainParseXMLIfDesc(virConnectPtr conn ATTRIBUTE_UNUSED, xmlNodePtr node, virBufferPtr buf, int hvm)
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
                   address element - eg ipv4 & ipv6. For now
                   xen only supports a single address though
                   so lets ignore that complication */
                ip = xmlGetProp(cur, BAD_CAST "address");
            }
        }
        cur = cur->next;
    }

    virBufferAdd(buf, "(vif ", 5);
    if (mac != NULL)
        virBufferVSprintf(buf, "(mac '%s')", (const char *) mac);
    if (source != NULL) {
        if (typ == 0)
            virBufferVSprintf(buf, "(bridge '%s')", (const char *) source);
        else if (typ == 1)      /* TODO does that work like that ? */
            virBufferVSprintf(buf, "(dev '%s')", (const char *) source);
        else {
            virNetworkPtr network = virNetworkLookupByName(conn, (const char *) source);
            char *bridge;
            if (!network || !(bridge = virNetworkGetBridgeName(network))) {
                virXMLError(conn, VIR_ERR_NO_SOURCE, (const char *) source, 0);
                goto error;
            }
            virBufferVSprintf(buf, "(bridge '%s')", bridge);
            free(bridge);
        }
    }
    if (script != NULL)
        virBufferVSprintf(buf, "(script '%s')", script);
    if (ip != NULL)
        virBufferVSprintf(buf, "(ip '%s')", ip);
    if (hvm)
        virBufferAdd(buf, "(type ioemu)", 12);

    virBufferAdd(buf, ")", 1);
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
 * create the comain. This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns the 0 terminatedi S-Expr string or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainParseXMLDesc(virConnectPtr conn, const char *xmldesc, char **name, int xendConfigVersion)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node;
    char *ret = NULL, *nam = NULL;
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
    ret = malloc(1000);
    if (ret == NULL)
        return (NULL);
    buf.content = ret;
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

    xml = xmlCtxtReadDoc(pctxt, (const xmlChar *) xmldesc, "domain.xml", NULL,
                         XML_PARSE_NOENT | XML_PARSE_NONET |
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
    virBufferAdd(&buf, "(vm ", 4);
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

    if ((virXPathNumber("number(/domain/currentMemory[1])", ctxt, &f) < 0) ||
        (f < MIN_XEN_GUEST_SIZE * 1024)) {
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

    str = virXPathString("string(/domain/uuid[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(uuid '%s')", str);
	free(str);
    }

    str = virXPathString("string(/domain/bootloader[1])", ctxt);
    if (str != NULL) {
        virBufferVSprintf(&buf, "(bootloader '%s')", str);
        /*
         * if using pygrub, the kernel and initrd strings are not
         * significant and should be discarded
         */
        if (strstr(str, "pygrub"))
            bootloader = 2;
        else
            bootloader = 1;
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

    if (bootloader != 2) {
        if ((node = virXPathNode("/domain/os[1]", ctxt)) != NULL) {
            /* Analyze of the os description, based on HVM or PV. */
	    str = virXPathString("string(/domain/os/type[1])", ctxt);

            if ((str == NULL) || (strcmp(str, "hvm"))) {
                res = virDomainParseXMLOSDescPV(conn, node,
                                                &buf, ctxt, xendConfigVersion);
            } else {
                hvm = 1;
                res = virDomainParseXMLOSDescHVM(conn, node, &buf, ctxt,
		                                 vcpus, xendConfigVersion);
            }

            if (str != NULL) free(str);

            if (res != 0)
                goto error;
        } else if (bootloader == 0) {
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
            virBufferAdd(&buf, "(device ", 8);
            res = virDomainParseXMLIfDesc(conn, nodes[i], &buf, hvm);
            if (res != 0) {
	        free(nodes);
                goto error;
            }
            virBufferAdd(&buf, ")", 1);
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


    virBufferAdd(&buf, ")", 1); /* closes (vm */
    buf.content[buf.use] = 0;

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlFreeParserCtxt(pctxt);

    if (name != NULL)
        *name = nam;
    else
        free(nam);

    return (ret);

 error:
    if (nam != NULL)
        free(nam);
    if (name != NULL)
        *name = NULL;
    if (ctxt != NULL)
        xmlXPathFreeContext(ctxt);
    if (xml != NULL)
        xmlFreeDoc(xml);
    if (pctxt != NULL)
        xmlFreeParserCtxt(pctxt);
    if (ret != NULL)
        free(ret);
    return (NULL);
}

#endif /* !PROXY */



unsigned char *virParseUUID(char **ptr, const char *uuid) {
    int rawuuid[VIR_UUID_BUFLEN];
    const char *cur;
    unsigned char *dst_uuid = NULL;
    int i;

    if (uuid == NULL)
        goto error;

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs as long as there is 32 of them in the end.
     */
    cur = uuid;
    for (i = 0;i < VIR_UUID_BUFLEN;) {
        rawuuid[i] = 0;
        if (*cur == 0)
            goto error;
        if ((*cur == '-') || (*cur == ' ')) {
            cur++;
            continue;
        }
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] = *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] = *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] = *cur - 'A' + 10;
        else
            goto error;
        rawuuid[i] *= 16;
        cur++;
        if (*cur == 0)
            goto error;
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] += *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] += *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] += *cur - 'A' + 10;
        else
            goto error;
        i++;
        cur++;
    }

    dst_uuid = (unsigned char *) *ptr;
    *ptr += 16;

    for (i = 0; i < VIR_UUID_BUFLEN; i++)
        dst_uuid[i] = rawuuid[i] & 0xFF;

 error:
    return(dst_uuid);
}

#ifndef PROXY
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
virParseXMLDevice(virConnectPtr conn, char *xmldesc, int hvm, int xendConfigVersion)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node;
    virBuffer buf;

    buf.content = malloc(1000);
    if (buf.content == NULL)
        return (NULL);
    buf.size = 1000;
    buf.use = 0;
    xml = xmlReadDoc((const xmlChar *) xmldesc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (xml == NULL)
        goto error;
    node = xmlDocGetRootElement(xml);
    if (node == NULL)
        goto error;
    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        if (virDomainParseXMLDiskDesc(conn, node, &buf, hvm, xendConfigVersion) != 0)
            goto error;
    }
    else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        if (virDomainParseXMLIfDesc(conn, node, &buf, hvm) != 0)
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
virDomainXMLDevID(virDomainPtr domain, char *xmldesc, char *class, char *ref)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node, cur;
    xmlChar *attr = NULL;
#ifdef WITH_XEN
    char *xref;
#endif /* WITH_XEN */
    int ret = 0;

    xml = xmlReadDoc((const xmlChar *) xmldesc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (xml == NULL)
        goto error;
    node = xmlDocGetRootElement(xml);
    if (node == NULL)
        goto error;
    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        strcpy(class, "vbd");
        for (cur = node->children; cur != NULL; cur = cur->next) {
            if ((cur->type != XML_ELEMENT_NODE) ||
                (!xmlStrEqual(cur->name, BAD_CAST "target"))) continue;
            attr = xmlGetProp(cur, BAD_CAST "dev");
            if (attr == NULL)
                goto error;
            strcpy(ref, (char *)attr);
            goto cleanup;
        }
    }
    else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        strcpy(class, "vif");
        for (cur = node->children; cur != NULL; cur = cur->next) {
            if ((cur->type != XML_ELEMENT_NODE) ||
                (!xmlStrEqual(cur->name, BAD_CAST "mac"))) continue;
            attr = xmlGetProp(cur, BAD_CAST "address");
            if (attr == NULL)
                goto error;

#ifdef WITH_XEN
            xref = xenStoreDomainGetNetworkID(domain->conn, domain->id,
                                              (char *) attr);
            if (xref != NULL) {
                strcpy(ref, xref);
                free(xref);
                goto cleanup;
            }
#else /* without xen */
            /* hack to avoid the warning that domain is unused */
            if (domain->id < 0)
	        ret = -1;
#endif /* WITH_XEN */

            goto error;
        }
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
#endif /* !PROXY */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
