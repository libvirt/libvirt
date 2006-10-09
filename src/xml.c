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
#include <xs.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <math.h> /* for isnan() */
#include "internal.h"
#include "hash.h"
#include "sexpr.h"
#include "xml.h"

static void
virXMLError(virErrorNumber error, const char *info, int value)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, VIR_FROM_XML, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}

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
        virXMLError(VIR_ERR_NO_MEMORY, _("growing buffer"), size);
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
        if (!virBufferGrow(buf, needSize)) {
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
        virXMLError(VIR_ERR_NO_MEMORY, _("allocate new buffer"), sizeof(*buf));
        return NULL;
    }
    if (size && (buf->content = malloc(size))==NULL) {
        virXMLError(VIR_ERR_NO_MEMORY, _("allocate buffer content"), size);
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
           if (!virBufferGrow(buf, needSize))
              return -1;
	}
        memcpy(&buf->content[buf->use], str, len);
        buf->use += len;
        buf->content[buf->use] = 0;
    }
    va_end(ap);
    return 0;
}

#if 0

/*
 * This block of function are now implemented by a xend poll in
 * xend_internal.c instead of querying the Xen store, code is kept
 * for reference of in case Xend may not be available in the future ...
 */

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
                          long dev, const char *name)
{
    char s[256];
    unsigned int len = 0;

    snprintf(s, 255, "/local/domain/0/backend/%s/%d/%ld/%s",
             sub, domain->handle, dev, name);
    s[255] = 0;

    return xs_read(domain->conn->xshandle, 0, &s[0], &len);
}

/**
 * virDomainGetXMLDevice:
 * @domain: a domain object
 * @buf: the output buffer object
 * @dev: the xenstrore internal device number
 *
 * Extract and dump in the buffer information on the device used by the domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLDevice(virDomainPtr domain, virBufferPtr buf, long dev)
{
    char *type, *val;

    type = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "type");
    if (type == NULL)
        return (-1);
    if (!strcmp(type, "file")) {
        virBufferVSprintf(buf, "    <disk type='file'>\n");
        val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "params");
        if (val != NULL) {
            virBufferVSprintf(buf, "      <source file='%s'/>\n", val);
            free(val);
        }
        val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "dev");
        if (val != NULL) {
            char *tmp = val;
            if (!strncmp(tmp, "ioemu:", 6))
                tmp += 6;
            virBufferVSprintf(buf, "      <target dev='%s'/>\n", tmp);
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
            char *tmp = val;
            if (!strncmp(tmp, "ioemu:", 6))
                tmp += 6;
            virBufferVSprintf(buf, "      <target dev='%s'/>\n", tmp);
            free(val);
        }
        val = virDomainGetXMLDeviceInfo(domain, "vbd", dev, "read-only");
        if (val != NULL) {
            virBufferVSprintf(buf, "      <readonly/>\n", val);
            free(val);
        }
        virBufferAdd(buf, "    </disk>\n", 12);
    } else {
        TODO fprintf(stderr, "Don't know how to handle device type %s\n",
                     type);
    }
    free(type);

    return (0);
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
virDomainGetXMLDevices(virDomainPtr domain, virBufferPtr buf)
{
    int ret = -1;
    unsigned int num, i;
    long id;
    char **list = NULL, *endptr;
    char backend[200];
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (-1);

    conn = domain->conn;

    snprintf(backend, 199, "/local/domain/0/backend/vbd/%d",
             virDomainGetID(domain));
    backend[199] = 0;
    list = xs_directory(conn->xshandle, 0, backend, &num);
    ret = 0;
    if (list == NULL)
        goto done;

    for (i = 0; i < num; i++) {
        id = strtol(list[i], &endptr, 10);
        if ((endptr == list[i]) || (*endptr != 0)) {
            ret = -1;
            goto done;
        }
        virDomainGetXMLDevice(domain, buf, id);
    }

  done:
    if (list != NULL)
        free(list);

    return (ret);
}

/**
 * virDomainGetXMLInterface:
 * @domain: a domain object
 * @buf: the output buffer object
 * @dev: the xenstrore internal device number
 *
 * Extract and dump in the buffer information on the interface used by
 * the domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLInterface(virDomainPtr domain, virBufferPtr buf, long dev)
{
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

    return (0);
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
virDomainGetXMLInterfaces(virDomainPtr domain, virBufferPtr buf)
{
    int ret = -1;
    unsigned int num, i;
    long id;
    char **list = NULL, *endptr;
    char backend[200];
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (-1);

    conn = domain->conn;

    snprintf(backend, 199, "/local/domain/0/backend/vif/%d",
             virDomainGetID(domain));
    backend[199] = 0;
    list = xs_directory(conn->xshandle, 0, backend, &num);
    ret = 0;
    if (list == NULL)
        goto done;

    for (i = 0; i < num; i++) {
        id = strtol(list[i], &endptr, 10);
        if ((endptr == list[i]) || (*endptr != 0)) {
            ret = -1;
            goto done;
        }
        virDomainGetXMLInterface(domain, buf, id);
    }

  done:
    if (list != NULL)
        free(list);

    return (ret);
}




/**
 * virDomainGetXMLBoot:
 * @domain: a domain object
 * @buf: the output buffer object
 *
 * Extract the boot information used to start that domain
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainGetXMLBoot(virDomainPtr domain, virBufferPtr buf)
{
    char *vm, *str;

    if (!VIR_IS_DOMAIN(domain))
        return (-1);

    vm = virDomainGetVM(domain);
    if (vm == NULL)
        return (-1);

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
    return (0);
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
virDomainGetXMLDesc(virDomainPtr domain, int flags)
{
    char *ret = NULL;
    unsigned char uuid[16];
    virBuffer buf;
    virDomainInfo info;

    if (!VIR_IS_DOMAIN(domain))
        return (NULL);
    if (flags != 0)
        return (NULL);
    if (virDomainGetInfo(domain, &info) < 0)
        return (NULL);

    ret = malloc(1000);
    if (ret == NULL)
        return (NULL);
    buf.content = ret;
    buf.size = 1000;
    buf.use = 0;

    virBufferVSprintf(&buf, "<domain type='xen' id='%d'>\n",
                      virDomainGetID(domain));
    virBufferVSprintf(&buf, "  <name>%s</name>\n",
                      virDomainGetName(domain));
    if (virDomainGetUUID(domain, &uuid[0]) == 0) {
    virBufferVSprintf(&buf,
"  <uuid>%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x</uuid>\n",
                      uuid[0], uuid[1], uuid[2], uuid[3],
                      uuid[4], uuid[5], uuid[6], uuid[7],
                      uuid[8], uuid[9], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);
    }
    virDomainGetXMLBoot(domain, &buf);
    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", info.maxMem);
    virBufferVSprintf(&buf, "  <vcpu>%d</vcpu>\n", (int) info.nrVirtCpu);
    virBufferAdd(&buf, "  <devices>\n", 12);
    virDomainGetXMLDevices(domain, &buf);
    virDomainGetXMLInterfaces(domain, &buf);
    virBufferAdd(&buf, "  </devices>\n", 13);
    virBufferAdd(&buf, "</domain>\n", 10);

    buf.content[buf.use] = 0;
    return (ret);
}

#endif /* 0 - UNUSED */

#ifndef PROXY
/**
 * virtDomainParseXMLGraphicsDesc:
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
static int virDomainParseXMLGraphicsDesc(xmlNodePtr node, virBufferPtr buf, int xendConfigVersion)
{
    xmlChar *graphics_type = NULL;

    graphics_type = xmlGetProp(node, BAD_CAST "type");
    if (graphics_type != NULL) {
        if (xmlStrEqual(graphics_type, BAD_CAST "sdl")) {
            virBufferAdd(buf, "(sdl 1)", 7);
            // TODO:
            // Need to understand sdl options
            //
            //virBufferAdd(buf, "(display localhost:10.0)", 24);
            //virBufferAdd(buf, "(xauthority /root/.Xauthority)", 30);
        }
        else if (xmlStrEqual(graphics_type, BAD_CAST "vnc")) {
            virBufferAdd(buf, "(vnc 1)", 7);
            if (xendConfigVersion >= 2) {
                xmlChar *vncport = xmlGetProp(node, BAD_CAST "port");
                if (vncport != NULL) {
                    long port = strtol((const char *)vncport, NULL, 10);
                    if (port == -1)
                        virBufferAdd(buf, "(vncunused 1)", 13);
                    else if (port > 5900)
                        virBufferVSprintf(buf, "(vncdisplay %d)", port - 5900);
                    xmlFree(vncport);
                }
            }
        }
        xmlFree(graphics_type);
    }
    return 0;
}


/**
 * virDomainParseXMLOSDescHVM:
 * @node: node containing HVM OS description
 * @buf: a buffer for the result S-Expr
 * @ctxt: a path context representing the XML description
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
virDomainParseXMLOSDescHVM(xmlNodePtr node, virBufferPtr buf, xmlXPathContextPtr ctxt, int xendConfigVersion)
{
    xmlXPathObjectPtr obj = NULL;
    xmlNodePtr cur, txt;
    xmlChar *type = NULL;
    xmlChar *loader = NULL;
    xmlChar *boot_dev = NULL;
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
            } else if ((loader == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "loader"))) {
                txt = cur->children;
                if ((txt != NULL) && (txt->type == XML_TEXT_NODE) &&
		    (txt->next == NULL))
                    loader = txt->content;
            } else if ((boot_dev == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "boot"))) {
                boot_dev = xmlGetProp(cur, BAD_CAST "dev");
            }
        }
        cur = cur->next;
    }
    if ((type == NULL) || (!xmlStrEqual(type, BAD_CAST "hvm"))) {
        /* VIR_ERR_OS_TYPE */
        virXMLError(VIR_ERR_OS_TYPE, (const char *) type, 0);
        return (-1);
    }
    virBufferAdd(buf, "(image (hvm ", 12);
    if (loader == NULL) {
       virXMLError(VIR_ERR_NO_KERNEL, NULL, 0);
       goto error;
    } else {
       virBufferVSprintf(buf, "(kernel '%s')", (const char *) loader);
    }

    /* get the device emulation model */
    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/emulator[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        virXMLError(VIR_ERR_NO_KERNEL, NULL, 0); /* TODO: error */
        goto error;
    }
    virBufferVSprintf(buf, "(device_model '%s')",
                      (const char *) obj->stringval);
    xmlXPathFreeObject(obj);
    obj = NULL;

    if (boot_dev) {
       if (xmlStrEqual(boot_dev, BAD_CAST "fd")) {
          virBufferVSprintf(buf, "(boot a)", (const char *) boot_dev);
       } else if (xmlStrEqual(boot_dev, BAD_CAST "cdrom")) {
          virBufferVSprintf(buf, "(boot d)", (const char *) boot_dev);
       } else if (xmlStrEqual(boot_dev, BAD_CAST "hd")) {
          virBufferVSprintf(buf, "(boot c)", (const char *) boot_dev);
       } else {
         /* Any other type of boot dev is unsupported right now */
         virXMLError(VIR_ERR_XML_ERROR, NULL, 0);
       }

       /* get the 1st floppy device file */
       obj = xmlXPathEval(BAD_CAST "/domain/devices/disk[@device='floppy' and target/@dev='fda']/source", ctxt);
       if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
           (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
           cur = obj->nodesetval->nodeTab[0];
           virBufferVSprintf(buf, "(fda '%s')",
                             (const char *) xmlGetProp(cur, BAD_CAST "file"));
           cur = NULL;
       }
       if (obj) {
           xmlXPathFreeObject(obj);
           obj = NULL;
       }

       /* get the 2nd floppy device file */
       obj = xmlXPathEval(BAD_CAST "/domain/devices/disk[@device='floppy' and target/@dev='fdb']/source", ctxt);
       if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
           (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
           xmlChar *fdfile = NULL;
           cur = obj->nodesetval->nodeTab[0];
           fdfile = xmlGetProp(cur, BAD_CAST "file");
           virBufferVSprintf(buf, "(fdb '%s')",
                             (const char *) fdfile);
           xmlFree(fdfile);
           cur = NULL;
       }
       if (obj) {
           xmlXPathFreeObject(obj);
           obj = NULL;
       }


       /* get the cdrom device file */
       /* Only XenD <= 3.0.2 wants cdrom config here */
       if (xendConfigVersion == 1) {
           obj = xmlXPathEval(BAD_CAST "/domain/devices/disk[@device='cdrom' and target/@dev='hdc']/source", ctxt);
           if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
               (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
               xmlChar *cdfile = NULL;
               cur = obj->nodesetval->nodeTab[0];
               cdfile = xmlGetProp(cur, BAD_CAST "file");
               virBufferVSprintf(buf, "(cdrom '%s')",
                                 (const char *)cdfile);
               xmlFree(cdfile);
               cur = NULL;
           }
           if (obj) {
               xmlXPathFreeObject(obj);
               obj = NULL;
           }
       }

       obj = xmlXPathEval(BAD_CAST "/domain/features/acpi", ctxt);
       if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
           (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
           virBufferAdd(buf, "(acpi 1)", 8);
       }
       if (obj)
           xmlXPathFreeObject(obj);
       obj = xmlXPathEval(BAD_CAST "/domain/features/apic", ctxt);
       if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
           (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
           virBufferAdd(buf, "(apic 1)", 8);
       }
       if (obj)
           xmlXPathFreeObject(obj);
       obj = xmlXPathEval(BAD_CAST "/domain/features/pae", ctxt);
       if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
           (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
           virBufferAdd(buf, "(pae 1)", 7);
       }
       if (obj)
           xmlXPathFreeObject(obj);
       obj = NULL;
    }

    obj = xmlXPathEval(BAD_CAST "count(domain/devices/console) > 0", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN)) {
      virXMLError(VIR_ERR_XML_ERROR, NULL, 0);
      goto error;
    }
    if (obj->boolval) {
      virBufferAdd(buf, "(serial pty)", 12);
    }
    xmlXPathFreeObject(obj);
    obj = NULL;
    
    /* Is a graphics device specified? */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/graphics[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        res = virDomainParseXMLGraphicsDesc(obj->nodesetval->nodeTab[0], buf, xendConfigVersion);
        if (res != 0) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    virBufferAdd(buf, "))", 2);

    if (boot_dev)
        xmlFree(boot_dev);

    return (0);
error:
    if (boot_dev)
        xmlFree(boot_dev);
    if (obj != NULL)
        xmlXPathFreeObject(obj);
    return(-1);
}

/**
 * virDomainParseXMLOSDescPV:
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
virDomainParseXMLOSDescPV(xmlNodePtr node, virBufferPtr buf, xmlXPathContextPtr ctxt, int xendConfigVersion)
{
    xmlNodePtr cur, txt;
    xmlXPathObjectPtr obj = NULL;
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
        virXMLError(VIR_ERR_OS_TYPE, (const char *) type, 0);
        return (-1);
    }
    virBufferAdd(buf, "(image (linux ", 14);
    if (kernel == NULL) {
      	virXMLError(VIR_ERR_NO_KERNEL, NULL, 0);
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

    /* Is a graphics device specified? */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/graphics[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        res = virDomainParseXMLGraphicsDesc(obj->nodesetval->nodeTab[0], buf, xendConfigVersion);
        if (res != 0) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

 error:
    virBufferAdd(buf, "))", 2);
    return (0);
}

/**
 * virDomainParseXMLDiskDesc:
 * @node: node containing disk description
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
virDomainParseXMLDiskDesc(xmlNodePtr node, virBufferPtr buf, int hvm, int xendConfigVersion)
{
    xmlNodePtr cur;
    xmlChar *type = NULL;
    xmlChar *device = NULL;
    xmlChar *source = NULL;
    xmlChar *target = NULL;
    xmlChar *drvName = NULL;
    xmlChar *drvType = NULL;
    int ro = 0;
    int typ = 0;
    int cdrom = 0;

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
            }
        }
        cur = cur->next;
    }

    if (source == NULL) {
        virXMLError(VIR_ERR_NO_SOURCE, (const char *) target, 0);

        if (target != NULL)
            xmlFree(target);
        if (device != NULL)
            xmlFree(device);
        return (-1);
    }
    if (target == NULL) {
        virXMLError(VIR_ERR_NO_TARGET, (const char *) source, 0);
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

    if (drvName) {
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
    } else {
        if (typ == 0)
            virBufferVSprintf(buf, "(uname 'file:%s')", source);
        else if (typ == 1) {
            if (source[0] == '/')
                virBufferVSprintf(buf, "(uname 'phy:%s')", source);
            else
                virBufferVSprintf(buf, "(uname 'phy:/dev/%s')", source);
        }
    }
    if (ro == 0)
        virBufferVSprintf(buf, "(mode 'w')");
    else if (ro == 1)
        virBufferVSprintf(buf, "(mode 'r')");

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
virDomainParseXMLIfDesc(xmlNodePtr node, virBufferPtr buf, int hvm)
{
    xmlNodePtr cur;
    xmlChar *type = NULL;
    xmlChar *source = NULL;
    xmlChar *mac = NULL;
    xmlChar *script = NULL;
    int typ = 0;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "bridge"))
            typ = 0;
        else if (xmlStrEqual(type, BAD_CAST "ethernet"))
            typ = 1;
        xmlFree(type);
    }
    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {

                if (typ == 0)
                    source = xmlGetProp(cur, BAD_CAST "bridge");
                else
                    source = xmlGetProp(cur, BAD_CAST "dev");
            } else if ((mac == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "mac"))) {
                mac = xmlGetProp(cur, BAD_CAST "address");
            } else if ((script == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "script"))) {
                script = xmlGetProp(cur, BAD_CAST "path");
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
        else                    /* TODO does that work like that ? */
            virBufferVSprintf(buf, "(dev '%s')", (const char *) source);
    }
    if (script != NULL)
        virBufferVSprintf(buf, "(script '%s')", script);
    if (hvm)
        virBufferAdd(buf, "(type ioemu)", 12);

    virBufferAdd(buf, ")", 1);
    if (mac != NULL)
        xmlFree(mac);
    if (source != NULL)
        xmlFree(source);
    if (script != NULL)
        xmlFree(script);
    return (0);
}

/**
 * virDomainParseXMLDesc:
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
virDomainParseXMLDesc(const char *xmldesc, char **name, int xendConfigVersion)
{
    xmlDocPtr xml = NULL;
    xmlNodePtr node;
    char *ret = NULL, *nam = NULL;
    virBuffer buf;
    xmlChar *prop;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathObjectPtr tmpobj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int i, res;
    int bootloader = 0;
    int hvm = 0;

    if (name != NULL)
        *name = NULL;
    ret = malloc(1000);
    if (ret == NULL)
        return (NULL);
    buf.content = ret;
    buf.size = 1000;
    buf.use = 0;

    xml = xmlReadDoc((const xmlChar *) xmldesc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
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
    obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        virXMLError(VIR_ERR_NO_NAME, xmldesc, 0);
        goto error;
    }
    virBufferVSprintf(&buf, "(name '%s')", obj->stringval);
    nam = strdup((const char *) obj->stringval);
    if (nam == NULL) {
        virXMLError(VIR_ERR_NO_MEMORY, "copying name", 0);
        goto error;
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "number(/domain/memory[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval)) || (obj->floatval < 64000)) {
        virBufferVSprintf(&buf, "(memory 128)(maxmem 128)");
    } else {
        unsigned long mem = (obj->floatval / 1024);

        virBufferVSprintf(&buf, "(memory %lu)(maxmem %lu)", mem, mem);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "number(/domain/vcpu[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval)) || (obj->floatval <= 0)) {
        virBufferVSprintf(&buf, "(vcpus 1)");
    } else {
        unsigned int cpu = (unsigned int) obj->floatval;

        virBufferVSprintf(&buf, "(vcpus %u)", cpu);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
    if ((obj == NULL) || ((obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0))) {
        virBufferVSprintf(&buf, "(uuid '%s')", obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/bootloader[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
	virBufferVSprintf(&buf, "(bootloader '%s')", obj->stringval);
	bootloader = 1;
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/on_poweroff[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
	virBufferVSprintf(&buf, "(on_poweroff '%s')", obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/on_reboot[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
	virBufferVSprintf(&buf, "(on_reboot '%s')", obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/on_crash[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
	virBufferVSprintf(&buf, "(on_crash '%s')", obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "/domain/os[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
	/* Analyze of the os description, based on HVM or PV. */
	tmpobj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1])", ctxt);
	if ((tmpobj != NULL) &&
	    ((tmpobj->type != XPATH_STRING) || (tmpobj->stringval == NULL) ||
	     (tmpobj->stringval[0] == 0))) {
	    xmlXPathFreeObject(tmpobj);
	    virXMLError(VIR_ERR_OS_TYPE, nam, 0);
	    goto error;
	}

	if ((tmpobj == NULL) || !xmlStrEqual(tmpobj->stringval, BAD_CAST "hvm")) {
	    res = virDomainParseXMLOSDescPV(obj->nodesetval->nodeTab[0], &buf, ctxt, xendConfigVersion);
	} else {
	    hvm = 1;
	    res = virDomainParseXMLOSDescHVM(obj->nodesetval->nodeTab[0], &buf, ctxt, xendConfigVersion);
	}

	xmlXPathFreeObject(tmpobj);

	if (res != 0)
	    goto error;
    } else if (bootloader == 0) {
	virXMLError(VIR_ERR_NO_OS, nam, 0);
	goto error;
    }
    xmlXPathFreeObject(obj);

    /* analyze of the devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
	for (i = 0; i < obj->nodesetval->nodeNr; i++) {
	  res = virDomainParseXMLDiskDesc(obj->nodesetval->nodeTab[i], &buf, hvm, xendConfigVersion);
	    if (res != 0) {
		goto error;
	    }
	}
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            virBufferAdd(&buf, "(device ", 8);
            res = virDomainParseXMLIfDesc(obj->nodesetval->nodeTab[i], &buf, hvm);
            if (res != 0) {
                goto error;
            }
            virBufferAdd(&buf, ")", 1);
        }
    }
    xmlXPathFreeObject(obj);


    virBufferAdd(&buf, ")", 1); /* closes (vm */
    buf.content[buf.use] = 0;

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

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
    if (obj != NULL)
        xmlXPathFreeObject(obj);
    if (ctxt != NULL)
        xmlXPathFreeContext(ctxt);
    if (xml != NULL)
        xmlFreeDoc(xml);
    if (ret != NULL)
        free(ret);
    return (NULL);
}

#endif /* !PROXY */



unsigned char *virParseUUID(char **ptr, const char *uuid) {
    int rawuuid[16];
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
    for (i = 0;i < 16;) {
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

    for (i = 0; i < 16; i++)
        dst_uuid[i] = rawuuid[i] & 0xFF;

error:
    return(dst_uuid);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
