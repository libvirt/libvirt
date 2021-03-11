/*
 * Copyright 2014, diateam (www.diateam.net)
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

#pragma once

#include "internal.h"

#define VBOX_UUID_REGEX "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"

/*Stores VirtualBox xml hard disk information
A hard disk can have a parent and children*/
typedef struct _virVBoxSnapshotConfHardDisk virVBoxSnapshotConfHardDisk;
struct _virVBoxSnapshotConfHardDisk {
    virVBoxSnapshotConfHardDisk *parent;
    char *uuid;
    char *location;
    char *format;
    char *type;
    size_t nchildren;
    virVBoxSnapshotConfHardDisk **children;
};

/*Stores Virtualbox xml media registry information
We separate disks from other media to manipulate them*/
typedef struct _virVBoxSnapshotConfMediaRegistry virVBoxSnapshotConfMediaRegistry;
struct _virVBoxSnapshotConfMediaRegistry {
    size_t ndisks;
    virVBoxSnapshotConfHardDisk **disks;
    size_t notherMedia;
    char **otherMedia;
};

/*Stores VirtualBox xml snapshot information
A snapshot can have a parent and children*/
typedef struct _virVBoxSnapshotConfSnapshot virVBoxSnapshotConfSnapshot;
struct _virVBoxSnapshotConfSnapshot {
    virVBoxSnapshotConfSnapshot *parent;
    char *uuid;
    char *name;
    char *timeStamp;
    char *description;
    char *hardware;
    char *storageController;
    size_t nchildren;
    virVBoxSnapshotConfSnapshot **children;
};

/*Stores VirtualBox xml Machine information*/
typedef struct _virVBoxSnapshotConfMachine virVBoxSnapshotConfMachine;
struct _virVBoxSnapshotConfMachine {
    char *uuid;
    char *name;
    char *currentSnapshot;
    char *snapshotFolder;
    int currentStateModified;
    char *lastStateChange;
    virVBoxSnapshotConfMediaRegistry *mediaRegistry;
    char *hardware;
    char *extraData;
    virVBoxSnapshotConfSnapshot *snapshot;
    char *storageController;
};

void
virVboxSnapshotConfHardDiskFree(virVBoxSnapshotConfHardDisk *disk);
void
virVBoxSnapshotConfMediaRegistryFree(virVBoxSnapshotConfMediaRegistry *mediaRegistry);
void
virVBoxSnapshotConfSnapshotFree(virVBoxSnapshotConfSnapshot *snapshot);
void
virVBoxSnapshotConfMachineFree(virVBoxSnapshotConfMachine *machine);

virVBoxSnapshotConfMachine *
virVBoxSnapshotConfLoadVboxFile(const char *filePath,
                                const char *machineLocation);
int
virVBoxSnapshotConfAddSnapshotToXmlMachine(virVBoxSnapshotConfSnapshot *snapshot,
                                           virVBoxSnapshotConfMachine *machine,
                                           const char *snapshotParentName);
int
virVBoxSnapshotConfAddHardDiskToMediaRegistry(virVBoxSnapshotConfHardDisk *hardDisk,
                                              virVBoxSnapshotConfMediaRegistry *mediaRegistry,
                                              const char *parentHardDiskId);
int
virVBoxSnapshotConfRemoveSnapshot(virVBoxSnapshotConfMachine *machine,
                                  const char *snapshotName);
int
virVBoxSnapshotConfRemoveHardDisk(virVBoxSnapshotConfMediaRegistry *mediaRegistry,
                                  const char *uuid);
int
virVBoxSnapshotConfSaveVboxFile(virVBoxSnapshotConfMachine *machine,
                                const char *filePath);
int
virVBoxSnapshotConfIsCurrentSnapshot(virVBoxSnapshotConfMachine *machine,
                                     const char *snapshotName);
int
virVBoxSnapshotConfGetRWDisksPathsFromLibvirtXML(const char *filePath,
                                                 char ***realReadWriteDisksPath);
int
virVBoxSnapshotConfGetRODisksPathsFromLibvirtXML(const char *filePath,
                                                 char ***realReadOnlyDisksPath);
const char *
virVBoxSnapshotConfHardDiskUuidByLocation(virVBoxSnapshotConfMachine *machine,
                                          const char *location);
size_t
virVBoxSnapshotConfDiskListToOpen(virVBoxSnapshotConfMachine *machine,
                                  virVBoxSnapshotConfHardDisk ***hardDiskToOpen,
                                  const char *location);
int
virVBoxSnapshotConfRemoveFakeDisks(virVBoxSnapshotConfMachine *machine);
int
virVBoxSnapshotConfDiskIsInMediaRegistry(virVBoxSnapshotConfMachine *machine,
                                         const char *location);
virVBoxSnapshotConfHardDisk *
virVBoxSnapshotConfHardDiskPtrByLocation(virVBoxSnapshotConfMachine *machine,
                                         const char *location);
virVBoxSnapshotConfSnapshot *
virVBoxSnapshotConfSnapshotByName(virVBoxSnapshotConfSnapshot *snapshot,
                                  const char *snapshotName);
