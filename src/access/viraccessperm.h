/*
 * viraccessperm.h: access control permissions
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __VIR_ACCESS_PERM_H__
# define __VIR_ACCESS_PERM_H__

# include "internal.h"
# include "virutil.h"

typedef enum {
    /**
     * @desc: Access connection
     * @message: Accessing the connection requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_GETATTR,

    /**
     * @desc: Read host
     * @message: Reading the host configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_READ,

    /**
     * @desc: Write host
     * @message: Writing the host configuration requires authorization
     */
    VIR_ACCESS_PERM_CONNECT_WRITE,

    /**
     * @desc: List domains
     * @message: Listing domains or using domain events requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_DOMAINS,

    /**
     * @desc: List networks
     * @message: Listing networks or using network events requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_NETWORKS,

    /**
     * @desc: List storage pools
     * @message: Listing storage pools requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_STORAGE_POOLS,

    /**
     * @desc: List node devices
     * @message: Listing node devices requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_NODE_DEVICES,

    /**
     * @desc: List interfaces
     * @message: Listing interfaces requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_INTERFACES,

    /**
     * @desc: List secrets
     * @message: Listing secrets requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_SECRETS,

    /**
     * @desc: List network filters
     * @message: Listing network filters requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_CONNECT_SEARCH_NWFILTERS,


    /**
     * @desc: Detect storage pools
     * @message: Detecting storage pools requires authorization
     */
    VIR_ACCESS_PERM_CONNECT_DETECT_STORAGE_POOLS,

    /**
     * @desc: Use host power management
     * @message: Using host power management requires authorization
     */
    VIR_ACCESS_PERM_CONNECT_PM_CONTROL,

    /**
     * @desc: Interface transactions
     * @message: Using interface transactions requires authorization
     */
    VIR_ACCESS_PERM_CONNECT_INTERFACE_TRANSACTION,

    VIR_ACCESS_PERM_CONNECT_LAST,
} virAccessPermConnect;

typedef enum {
    /**
     * @desc: Access domain
     * @message: Accessing the domain requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_DOMAIN_GETATTR,     /* Name/ID/UUID access */

    /**
     * @desc: Read domain
     * @message: Reading domain configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_DOMAIN_READ,        /* Config view */

    /**
     * @desc: Write domain
     * @message: Writing domain configuration requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_WRITE,       /* Config change */

    /**
     * @desc: Read secure domain
     * @message: Reading secure domain configuration requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_READ_SECURE, /* Config access of passwords */

    /**
     * @desc: Start domain
     * @message: Starting the domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_START,  /* Power on */

    /**
     * @desc: Stop domain
     * @message: Stopping the domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_STOP,   /* Power off */

    /**
     * @desc: Reset domain
     * @message: Resetting the domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_RESET,  /* Power reset */

    /**
     * @desc: Save domain
     * @message: Saving domain configuration requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SAVE,   /* Write out persistent config */

    /**
     * @desc: Delete domain
     * @message: Deleting domain configuration requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_DELETE, /* Remove persistent config */


    /**
     * @desc: Migrate domain
     * @message: Migrating domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_MIGRATE,   /* Host migration */

    /**
     * @desc: Snapshot domain
     * @message: Snapshotting domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SNAPSHOT,  /* Snapshot disks/memory */

    /**
     * @desc: Suspend domain
     * @message: Suspending domain CPUs requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SUSPEND,   /* Pause/resume CPUs */

    /**
     * @desc: Hibernate domain
     * @message: Saving domain state requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_HIBERNATE, /* Save state to host */

    /**
     * @desc: Dump domain
     * @message: Dumping domain corefile requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_CORE_DUMP, /* Dump guest core */

    /**
     * @desc: Use domain power management
     * @message: Using domain power management requires authoriation
     */
    VIR_ACCESS_PERM_DOMAIN_PM_CONTROL,  /* S3/S5 suspend/wakeup */

    /* Interactions with guest OS */

    /**
     * @desc: Domain init control
     * @message: Controlling domain init process requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_INIT_CONTROL, /* Init shutdown/reboot request */

    /**
     * @desc: Inject domain NMI
     * @message: Injecting interrupt requries authoriation
     */
    VIR_ACCESS_PERM_DOMAIN_INJECT_NMI,   /* Trigger interrupts */

    /**
     * @desc: Send domain input
     * @message: Sending input events to domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SEND_INPUT,   /* Send guest input device (key/mouse) events */

    /**
     * @desc: Send domain signal
     * @message: Sending signals to processes in domain requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SEND_SIGNAL,  /* Send a signal to processes inside */

    /**
     * @desc: Trim domain filesystems
     * @message: Trimming domain filesystems require authorization
     */
    VIR_ACCESS_PERM_DOMAIN_FS_TRIM,      /* Issue TRIM to guest filesystems */

    /* Peeking at guest */

    /**
     * @desc: Read domain block
     * @message: Reading domain block devices requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_BLOCK_READ,  /* Read data from block devices */

    /**
     * @desc: Write domain block
     * @message: Writing domain block devices requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_BLOCK_WRITE, /* resize/pull/rebase/commit */

    /**
     * @desc: Read domain memory
     * @message: Reading domain memory requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_MEM_READ,    /* Read data from guest memory */

    /* Device interaction */

    /**
     * @desc: Open domain graphics
     * @message: Opening domain graphics console requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_OPEN_GRAPHICS, /* Open graphical console */

    /**
     * @desc: Open domain device
     * @message: Opening domain devices requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_OPEN_DEVICE,   /* Open a guest console/channel */

    /**
     * @desc: Take domain screenshot
     * @message: Taking domain screenshots requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_SCREENSHOT,    /* Trigger a screen shot */


    /**
     * @desc: Open domain namespace
     * @message: Opening domain namespaces requires authorization
     */
    VIR_ACCESS_PERM_DOMAIN_OPEN_NAMESPACE,

    VIR_ACCESS_PERM_DOMAIN_LAST,
} virAccessPermDomain;

typedef enum {

    /**
     * @desc: Access interface
     * @message: Accessing interface requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_INTERFACE_GETATTR,

    /**
     * @desc: Read interface
     * @message: Reading interface configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_INTERFACE_READ,

    /**
     * @desc: Write interface
     * @message: Writing interface configuration requires authorization
     */
    VIR_ACCESS_PERM_INTERFACE_WRITE,

    /**
     * @desc: Save interface
     * @message: Saving interface configuration requires authorization
     */
    VIR_ACCESS_PERM_INTERFACE_SAVE,

    /**
     * @desc: Delete interface
     * @message: Deleting interface configuration requires authorization
     */
    VIR_ACCESS_PERM_INTERFACE_DELETE,

    /**
     * @desc: Start interface
     * @message: Starting interface requires authorization
     */
    VIR_ACCESS_PERM_INTERFACE_START,

    /**
     * @desc: Stop interface
     * @message: Stopping interface requires authorization
     */
    VIR_ACCESS_PERM_INTERFACE_STOP,

    VIR_ACCESS_PERM_INTERFACE_LAST
} virAccessPermInterface;

typedef enum {

    /**
     * @desc: Access network
     * @message: Accessing network requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_NETWORK_GETATTR,

    /**
     * @desc: Read network
     * @message: Reading network configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_NETWORK_READ,

    /**
     * @desc: Write network
     * @message: Writing network configuration requries authorization
     */
    VIR_ACCESS_PERM_NETWORK_WRITE,

    /**
     * @desc: Save network
     * @message: Saving network configuration requires authorization
     */
    VIR_ACCESS_PERM_NETWORK_SAVE,

    /**
     * @desc: Delete network
     * @message: Deleting network configuration requires authorization
     */
    VIR_ACCESS_PERM_NETWORK_DELETE,

    /**
     * @desc: Start network
     * @message: Starting network requires authorization
     */
    VIR_ACCESS_PERM_NETWORK_START,

    /**
     * @desc: Stop network
     * @message: Stopping network requires authorization
     */
    VIR_ACCESS_PERM_NETWORK_STOP,

    VIR_ACCESS_PERM_NETWORK_LAST
} virAccessPermNetwork;

typedef enum {

    /**
     * @desc: Access node device
     * @message: Accesing node device requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_NODE_DEVICE_GETATTR,

    /**
     * @desc: Read node device
     * @message: Reading node device configuration requires authorization
     */
    VIR_ACCESS_PERM_NODE_DEVICE_READ,

    /**
     * @desc: Write node device
     * @message: Writing node device configuration requires authorization
     */
    VIR_ACCESS_PERM_NODE_DEVICE_WRITE,

    /**
     * @desc: Start node device
     * @message: Starting node device requires authorization
     */
    VIR_ACCESS_PERM_NODE_DEVICE_START,

    /**
     * @desc: Stop node device
     * @message: Stopping node device requires authorization
     */
    VIR_ACCESS_PERM_NODE_DEVICE_STOP,

    /**
     * @desc: Detach node device
     * @message: Detaching node device driver requires authorization
     */
    VIR_ACCESS_PERM_NODE_DEVICE_DETACH,

    VIR_ACCESS_PERM_NODE_DEVICE_LAST
} virAccessPermNodeDevice;

typedef enum {

    /**
     * @desc: Access network filter
     * @message: Accessing network filter requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_NWFILTER_GETATTR,

    /**
     * @desc: Read network filter
     * @message: Reading network filter configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_NWFILTER_READ,

    /**
     * @desc: Write network filter
     * @message: Writing network filter configuration requires authorization
     */
    VIR_ACCESS_PERM_NWFILTER_WRITE,

    /**
     * @desc: Save network filter
     * @message: Saving network filter configuration requires authorization
     */
    VIR_ACCESS_PERM_NWFILTER_SAVE,

    /**
     * @desc: Delete network filter
     * @message: Deleting network filter configuration requires authorization
     */
    VIR_ACCESS_PERM_NWFILTER_DELETE,

    VIR_ACCESS_PERM_NWFILTER_LAST
} virAccessPermNWFilter;

typedef enum {

    /**
     * @desc: Access secret
     * @message: Accessing secret requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_SECRET_GETATTR,

    /**
     * @desc: Read secret
     * @message: Reading secret configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_SECRET_READ,

    /**
     * @desc: Write secret
     * @message: Writing secret configuration requires authorization
     */
    VIR_ACCESS_PERM_SECRET_WRITE,

    /**
     * @desc: Read secure secret
     * @message: Reading secure secret configuration requires authorization
     */
    VIR_ACCESS_PERM_SECRET_READ_SECURE,

    /**
     * @desc: Save secret
     * @message: Saving secret configuration requires authorization
     */
    VIR_ACCESS_PERM_SECRET_SAVE,

    /**
     * @desc: Delete secret
     * @message: Deleting secret configuration requires authorization
     */
    VIR_ACCESS_PERM_SECRET_DELETE,

    VIR_ACCESS_PERM_SECRET_LAST
} virAccessPermSecret;

typedef enum {

    /**
     * @desc: Access storage pool
     * @message: Accessing storage pool requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_STORAGE_POOL_GETATTR,

    /**
     * @desc: Read storage pool
     * @message: Reading storage pool configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_STORAGE_POOL_READ,

    /**
     * @desc: Write storage pool
     * @message: Writing storage pool configuration requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_WRITE,

    /**
     * @desc: Save storage pool
     * @message: Saving storage pool configuration requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_SAVE,

    /**
     * @desc: Delete storage pool
     * @message: Deleting storage pool configuration requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_DELETE,

    /**
     * @desc: Start storage pool
     * @message: Starting storage pool configuration requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_START,

    /**
     * @desc: Stop storage pool
     * @message: Stopping storage pool configuration requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_STOP,

    /**
     * @desc: Refresh storage pool
     * @message: Refreshing storage pool volumes requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_REFRESH,

    /**
     * @desc: List storage pool volumes
     * @message: Listing storage pool volumes requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_SEARCH_STORAGE_VOLS,

    /**
     * @desc: Format storage pool
     * @message: Formatting storage pool data requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_POOL_FORMAT,

    VIR_ACCESS_PERM_STORAGE_POOL_LAST
} virAccessPermStoragePool;

typedef enum {

    /**
     * @desc: Access storage volume
     * @message: Acceessing storage volume requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_STORAGE_VOL_GETATTR,

    /**
     * @desc: Read storage volume
     * @message: Reading storage volume configuration requires authorization
     * @anonymous: 1
     */
    VIR_ACCESS_PERM_STORAGE_VOL_READ,

    /**
     * @desc: Create storage volume
     * @message: Creating storage volume requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_CREATE,

    /**
     * @desc: Delete storage volume
     * @message: Deleting storage volume requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_DELETE,

    /**
     * @desc: Format storage volume
     * @message: Formatting storage volume data requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_FORMAT,

    /**
     * @desc: Resize storage volume
     * @message: Resizing  storage volume requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_RESIZE,

    /**
     * @desc: Read storage volume data
     * @message: Reading storage volume data requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_DATA_READ,

    /**
     * @desc: Write storage volume data
     * @message: Writing storage volume data requires authorization
     */
    VIR_ACCESS_PERM_STORAGE_VOL_DATA_WRITE,

    VIR_ACCESS_PERM_STORAGE_VOL_LAST
} virAccessPermStorageVol;

VIR_ENUM_DECL(virAccessPermConnect);
VIR_ENUM_DECL(virAccessPermDomain);
VIR_ENUM_DECL(virAccessPermInterface);
VIR_ENUM_DECL(virAccessPermNetwork);
VIR_ENUM_DECL(virAccessPermNodeDevice);
VIR_ENUM_DECL(virAccessPermNWFilter);
VIR_ENUM_DECL(virAccessPermSecret);
VIR_ENUM_DECL(virAccessPermStoragePool);
VIR_ENUM_DECL(virAccessPermStorageVol);

#endif /* __VIR_ACCESS_PERM_H__ */
