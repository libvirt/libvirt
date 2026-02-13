/*
 * hyperv_driver.h: core driver functions for managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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
 *
 */

#pragma once

#define HYPERV_MAX_SCSI_CONTROLLERS 4
#define HYPERV_MAX_DRIVES_PER_SCSI_CONTROLLER 64
#define HYPERV_MAX_IDE_CHANNELS 2
#define HYPERV_MAX_DRIVES_PER_IDE_CHANNEL 2

#define HYPERV_VM_GEN1 "Microsoft:Hyper-V:SubType:1"
#define HYPERV_VM_GEN2 "Microsoft:Hyper-V:SubType:2"

/* ResourceSubType values for Msvm_*AllocationSettingData */
#define HYPERV_RESOURCE_SUBTYPE_SCSI_CONTROLLER "Microsoft:Hyper-V:Synthetic SCSI Controller"
#define HYPERV_RESOURCE_SUBTYPE_DISK_DRIVE "Microsoft:Hyper-V:Synthetic Disk Drive"
#define HYPERV_RESOURCE_SUBTYPE_VIRTUAL_HARD_DISK "Microsoft:Hyper-V:Virtual Hard Disk"
#define HYPERV_RESOURCE_SUBTYPE_PHYSICAL_DISK_DRIVE "Microsoft:Hyper-V:Physical Disk Drive"
#define HYPERV_RESOURCE_SUBTYPE_DVD_DRIVE "Microsoft:Hyper-V:Synthetic DVD Drive"
#define HYPERV_RESOURCE_SUBTYPE_VIRTUAL_DVD_DISK "Microsoft:Hyper-V:Virtual CD/DVD Disk"
#define HYPERV_RESOURCE_SUBTYPE_VIRTUAL_FLOPPY_DISK "Microsoft:Hyper-V:Virtual Floppy Disk"
#define HYPERV_RESOURCE_SUBTYPE_ETHERNET_PORT "Microsoft:Hyper-V:Synthetic Ethernet Port"
#define HYPERV_RESOURCE_SUBTYPE_ETHERNET_CONNECTION "Microsoft:Hyper-V:Ethernet Connection"

int hypervRegister(void);
