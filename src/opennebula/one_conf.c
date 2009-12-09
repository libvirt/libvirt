/*----------------------------------------------------------------------------------*/
/* Copyright 2002-2009, Distributed Systems Architecture Group, Universidad
 * Complutense de Madrid (dsa-research.org)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
/*-----------------------------------------------------------------------------------*/

#include <config.h>
#include <sys/utsname.h>

#include "virterror_internal.h"
#include "one_conf.h"
#include "buf.h"
#include "memory.h"
#include "util.h"

#define VIR_FROM_THIS VIR_FROM_ONE
/* --------------------------------------------------------------------------------- */

/**
 * oneCapsInit initialize the driver capabilities
 * @return a pointer to the driver capabilities NULL in case of error
 */

virCapsPtr oneCapsInit(void)
{
    struct utsname  utsname;
    virCapsPtr      caps;
    virCapsGuestPtr guest;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,0,0)) == NULL)
    {
        goto no_memory;
    }

    virCapabilitiesSetMacPrefix(caps,(unsigned char[]){ 0x52, 0x54, 0x00 });

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         "i686",
                                         32,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
    {
        goto no_memory;
    }

    if (virCapabilitiesAddGuestDomain(guest,
                                      "one",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
    {
        goto no_memory;
    }


    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         "x86_64",
                                         64,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
    {
        goto no_memory;
    }

    if (virCapabilitiesAddGuestDomain(guest,
                                      "one",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
    {
        goto no_memory;
    }
    if ((guest = virCapabilitiesAddGuest(caps,
                                         "xen",
                                         "i686",
                                         32,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
    {
        goto no_memory;
    }
    if (virCapabilitiesAddGuestDomain(guest,
                                      "one",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
    {
        goto no_memory;
    }

    return caps;

no_memory:

    virCapabilitiesFree(caps);
    return NULL;
}

/* --------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------- */


/**
 * oneSubmitVM generates an OpenNebula description file and submits the new VM
 * @param driver the OpenNebula driver
 * @param vm the virtual machine pointer
 * @return the OpenNebula ID for the new VM or -1 in case of error
 */

int oneSubmitVM(virConnectPtr    conn,
                one_driver_t*    driver ATTRIBUTE_UNUSED,
                virDomainObjPtr  vm)
{
    char* templ;
    int   oneid;

    if ((templ = xmlOneTemplate(conn,vm->def)) == NULL)
        return -1;

    if ((oneid = c_oneAllocateTemplate(templ)) < 0) {
        oneError(conn, NULL, VIR_ERR_OPERATION_FAILED,
                 "%s", _("Error submitting virtual machine to OpenNebula"));
        VIR_FREE(templ);
        return -1;
    }

    VIR_FREE(templ);
    return oneid;
}
/* --------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------- */

/**
 * xmlOneTemplate Generate an OpenNebula template to deploy a VM from libvirt
 * internal Domain definition.
 * @param def  Internal libvirt Domain definition
 * @return OpenNebula VM template.
 */

char* xmlOneTemplate(virConnectPtr conn,virDomainDefPtr def)
{
    int i;
    virBuffer buf= VIR_BUFFER_INITIALIZER;
    virBufferVSprintf(&buf,"#OpenNebula Template automatically generated by libvirt\nNAME = %s\nCPU = %ld\nMEMORY = %ld\n",
                      def->name,
                      def->vcpus,
                      (def->maxmem)/1024);

    /*Optional Booting OpenNebula Information:*/
    if (def->os.kernel) {
        virBufferVSprintf(&buf,"OS=[ kernel = \"%s\"",def->os.kernel);
        if (def->os.initrd)
            virBufferVSprintf(&buf,",\n    initrd = \"%s\"",def->os.initrd);
        if (def->os.cmdline)
            virBufferVSprintf(&buf,",\n    kernel_cmd = \"%s\"",def->os.cmdline);
        if (def->os.root)
            virBufferVSprintf(&buf,",\n    root  = \"%s\"",def->os.root);

        virBufferAddLit(&buf," ]\n");
    }
    /* set Disks & NICS */
    for (i=0 ; i < def->ndisks ; i++) {
        // missing source is only allowed at cdrom and floppy
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            virBufferVSprintf(&buf, "DISK=[ type = disk,\n"
                              "\tsource = \"%s\",\n",
                              def->disks[i]->src);
        }
        else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
            virBufferAddLit(&buf,  "DISK=[ type = cdrom,\n");
            if (def->disks[i]->src) virBufferVSprintf(&buf, "\tsource = \"%s\",\n",def->disks[i]->src);
        }
        else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            virBufferAddLit(&buf,  "DISK=[ type = floppy,\n");
            if (def->disks[i]->src) virBufferVSprintf(&buf, "\tsource = \"%s\",\n",def->disks[i]->src);
        }

        virBufferVSprintf(&buf, "\ttarget = \"%s\",\n"
                          "\treadonly =",
                          def->disks[i]->dst);

        if (def->disks[i]->readonly)
            virBufferAddLit(&buf,"\"yes\"]\n");
        else
            virBufferAddLit(&buf,"\"no\"]\n");
    }

    for (i=0 ; i< def->nnets ; i++)
    {
        if (!def->nets[i]) {
            continue;
        }

        switch(def->nets[i]->type)
        {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            virBufferVSprintf(&buf,"NIC=[ bridge =\"%s\",\n",def->nets[i]->data.bridge.brname);

            if (def->nets[i]->ifname)
                virBufferVSprintf(&buf,"      target =\"%s\",\n",def->nets[i]->ifname);

            virBufferVSprintf(&buf,"      mac =\"%02x:%02x:%02x:%02x:%02x:%02x\" ]\n",
                              def->nets[i]->mac[0],def->nets[i]->mac[1],
                              def->nets[i]->mac[2],def->nets[i]->mac[3],
                              def->nets[i]->mac[4],def->nets[i]->mac[5]);
            break;

        case VIR_DOMAIN_NET_TYPE_NETWORK:
            virBufferVSprintf(&buf,"NIC=[ network=\"%s\"",def->nets[i]->data.network.name);
            if (def->nets[i]->ifname)
                virBufferVSprintf(&buf,",\n      target =\"%s\"",def->nets[i]->ifname);
            virBufferAddLit(&buf," ]\n");
            break;

        default: break;
        }
    }

    for(i=0;i<def->ngraphics;i++) {
        if (def->graphics[i] == NULL)
            continue;

        if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            virBufferAddLit(&buf,"GRAPHICS = [\n  type = \"vnc\"");

            if (def->graphics[i]->data.vnc.listenAddr != NULL)
                virBufferVSprintf(&buf,",\n  listen = \"%s\"",
                    def->graphics[i]->data.vnc.listenAddr);

            if (def->graphics[i]->data.vnc.autoport == 0)
                virBufferVSprintf(&buf,",\n  port = \"%d\"",
                    def->graphics[i]->data.vnc.port);

            if (def->graphics[i]->data.vnc.passwd != NULL)
                virBufferVSprintf(&buf,",\n  passwd = \"%s\"",
                    def->graphics[i]->data.vnc.passwd);

            virBufferAddLit(&buf," ]\n");

        }
        else //graphics.type==VIR_DOMAIN_GRAPHICS_TYPE_SDL
            virBufferAddLit(&buf,"GRAPHICS = [\n  type = \"sdl\" ]\n");

    }
    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

no_memory:
    virReportOOMError(conn);
    virBufferFreeAndReset(&buf);
    return NULL;
};
