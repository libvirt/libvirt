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

#include <config.h>

#include "vbox_snapshot_conf.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virxml.h"

#include <libxml/xpathInternals.h>

#define VIR_FROM_THIS VIR_FROM_VBOX
VIR_LOG_INIT("vbox.vbox_snapshot_conf");

static virVBoxSnapshotConfHardDiskPtr
virVBoxSnapshotConfCreateVBoxSnapshotConfHardDiskPtr(xmlNodePtr diskNode,
                                                     xmlXPathContextPtr xPathContext,
                                                     const char *machineLocation)
{
    virVBoxSnapshotConfHardDiskPtr hardDisk = NULL;
    xmlNodePtr *nodes = NULL;
    char *uuid = NULL;
    char **searchTabResult = NULL;
    int resultSize = 0;
    size_t i = 0;
    int result = -1;
    char *location = NULL;
    char *tmp = NULL;
    int n = 0;
    if (VIR_ALLOC(hardDisk) < 0)
        goto cleanup;

    xPathContext->node = diskNode;

    n = virXPathNodeSet("./vbox:HardDisk", xPathContext, &nodes);
    if (n < 0)
        goto cleanup;

    if (n && VIR_ALLOC_N(hardDisk->children, n) < 0)
        goto cleanup;
    hardDisk->nchildren = n;
    for (i = 0; i < hardDisk->nchildren; i++) {
        hardDisk->children[i] = virVBoxSnapshotConfCreateVBoxSnapshotConfHardDiskPtr(nodes[i], xPathContext, machineLocation);
        if (hardDisk->children[i] == NULL)
            goto cleanup;
        hardDisk->children[i]->parent = hardDisk;
    }
    uuid = virXMLPropString(diskNode, "uuid");
    /*we use virStringSearch because the uuid is between brackets*/
    resultSize = virStringSearch(uuid,
                                 VBOX_UUID_REGEX,
                                 1,
                                 &searchTabResult);
    if (resultSize != 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <HardDisk> 'uuid' attribute"));
        goto cleanup;
    }
    if (VIR_STRDUP(hardDisk->uuid, searchTabResult[0]) < 0)
        goto cleanup;

    location = virXMLPropString(diskNode, "location");
    if (location == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <HardDisk> 'location' attribute"));
        goto cleanup;
    }
    if (location[0] != '/') {
        /*The location is a relative path, so we must change it into an absolute one. */
        if (virAsprintf(&tmp, "%s%s", machineLocation, location) < 0)
            goto cleanup;
        if (VIR_STRDUP(hardDisk->location, tmp) < 0)
            goto cleanup;
    } else {
        if (VIR_STRDUP(hardDisk->location, location) < 0)
            goto cleanup;
    }
    hardDisk->format = virXMLPropString(diskNode, "format");
    if (hardDisk->format == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <HardDisk> 'format' attribute"));
        goto cleanup;
    }
    hardDisk->type = virXMLPropString(diskNode, "type");
    result = 0;

 cleanup:
    VIR_FREE(uuid);
    VIR_FREE(nodes);
    VIR_FREE(location);
    VIR_FREE(tmp);
    virStringListFree(searchTabResult);
    if (result < 0) {
        virVboxSnapshotConfHardDiskFree(hardDisk);
        hardDisk = NULL;
    }
    return hardDisk;
}

static virVBoxSnapshotConfMediaRegistryPtr
virVBoxSnapshotConfRetrieveMediaRegistry(xmlNodePtr mediaRegistryNode,
                                         xmlXPathContextPtr xPathContext,
                                         const char *machineLocation)
{
    virVBoxSnapshotConfMediaRegistryPtr mediaRegistry = NULL;
    xmlNodePtr hardDisksNode = NULL;
    xmlNodePtr *nodes = NULL;
    size_t i = 0;
    int result = -1;
    int n = 0;

    if (VIR_ALLOC(mediaRegistry) < 0)
        goto cleanup;

    xPathContext->node = mediaRegistryNode;
    hardDisksNode = virXPathNode("./vbox:HardDisks", xPathContext);

    xPathContext->node = hardDisksNode;
    n = virXPathNodeSet("./vbox:HardDisk", xPathContext, &nodes);
    if (n < 0)
        goto cleanup;
    if (n && VIR_ALLOC_N(mediaRegistry->disks, n) < 0)
        goto cleanup;
    mediaRegistry->ndisks = n;
    for (i = 0; i < mediaRegistry->ndisks; i++) {
        mediaRegistry->disks[i] = virVBoxSnapshotConfCreateVBoxSnapshotConfHardDiskPtr(nodes[i],
                                                                   xPathContext,
                                                                   machineLocation);
        if (mediaRegistry->disks[i] == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot create a vboxSnapshotXmlHardDisk"));
            goto cleanup;
        }
    }
    n = 0;
    VIR_FREE(nodes);

    xPathContext->node = mediaRegistryNode;
    n = virXPathNodeSet("./*[not(self::vbox:HardDisks)]",
                                                 xPathContext, &nodes);
    if (n < 0)
        goto cleanup;
    if (n && VIR_ALLOC_N(mediaRegistry->otherMedia, n) < 0)
        goto cleanup;
    mediaRegistry->notherMedia = n;
    for (i = 0; i < mediaRegistry->notherMedia; i++) {
        mediaRegistry->otherMedia[i] = virXMLNodeToString(mediaRegistryNode->doc,
                                                          nodes[i]);
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virVBoxSnapshotConfMediaRegistryFree(mediaRegistry);
        mediaRegistry = NULL;
    }
    VIR_FREE(nodes);
    return mediaRegistry;
}

static virVBoxSnapshotConfSnapshotPtr
virVBoxSnapshotConfRetrieveSnapshot(xmlNodePtr snapshotNode,
                                    xmlXPathContextPtr xPathContext)
{
    virVBoxSnapshotConfSnapshotPtr snapshot = NULL;
    xmlNodePtr hardwareNode = NULL;
    xmlNodePtr descriptionNode = NULL;
    xmlNodePtr storageControllerNode = NULL;
    xmlNodePtr snapshotsNode = NULL;
    xmlNodePtr *nodes = NULL;
    char *uuid = NULL;
    char **searchTabResult = NULL;
    int resultSize = 0;
    size_t i = 0;
    int result = -1;
    int n = 0;

    if (VIR_ALLOC(snapshot) < 0)
        goto cleanup;

    uuid = virXMLPropString(snapshotNode, "uuid");
    /*we use virStringSearch because the uuid is between brackets*/
    resultSize = virStringSearch(uuid,
                                 VBOX_UUID_REGEX,
                                 1,
                                 &searchTabResult);
    if (resultSize != 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Snapshot> 'uuid' attribute"));
        goto cleanup;
    }
    if (VIR_STRDUP(snapshot->uuid, searchTabResult[0]) < 0)
        goto cleanup;

    snapshot->name = virXMLPropString(snapshotNode, "name");
    if (snapshot->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Snapshot> 'name' attribute"));
        goto cleanup;
    }
    snapshot->timeStamp = virXMLPropString(snapshotNode, "timeStamp");
    if (snapshot->timeStamp == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Snapshot> 'timeStamp' attribute"));
        goto cleanup;
    }

    xPathContext->node = snapshotNode;
    descriptionNode = virXPathNode("./vbox:Description", xPathContext);
    if (descriptionNode != NULL)
        snapshot->description = virXMLNodeToString(descriptionNode->doc, descriptionNode);

    hardwareNode = virXPathNode("./vbox:Hardware", xPathContext);
    if (hardwareNode == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Snapshot> <Hardware> node"));
        goto cleanup;
    }
    snapshot->hardware = virXMLNodeToString(snapshotNode->doc, hardwareNode);

    storageControllerNode = virXPathNode("./vbox:StorageControllers", xPathContext);
    if (storageControllerNode == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Snapshot> <StorageControllers> node"));
        goto cleanup;
    }
    snapshot->storageController = virXMLNodeToString(snapshotNode->doc,
                                                     storageControllerNode);

    snapshotsNode = virXPathNode("./vbox:Snapshots", xPathContext);

    if (snapshotsNode != NULL) {
        xPathContext->node = snapshotsNode;
        n = virXPathNodeSet("./vbox:Snapshot", xPathContext, &nodes);
        if (n < 0)
            goto cleanup;
        if (n && VIR_ALLOC_N(snapshot->children, n) < 0)
            goto cleanup;
        snapshot->nchildren = n;
        for (i = 0; i < snapshot->nchildren; i++) {
            snapshot->children[i] = virVBoxSnapshotConfRetrieveSnapshot(nodes[i], xPathContext);
            if (snapshot->children[i] == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Cannot create a vboxSnapshotXmlSnapshotPtr"));
                goto cleanup;
            }
            snapshot->children[i]->parent = snapshot;
        }
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virVBoxSnapshotConfSnapshotFree(snapshot);
        snapshot = NULL;
    }
    VIR_FREE(nodes);
    VIR_FREE(uuid);
    virStringListFree(searchTabResult);
    return snapshot;
}

virVBoxSnapshotConfSnapshotPtr
virVBoxSnapshotConfSnapshotByName(virVBoxSnapshotConfSnapshotPtr snapshot,
                                  const char *snapshotName)
{
    size_t i = 0;
    virVBoxSnapshotConfSnapshotPtr ret = NULL;
    if (STREQ(snapshot->name, snapshotName))
        return snapshot;
    for (i = 0; i < snapshot->nchildren; i++) {
        ret = virVBoxSnapshotConfSnapshotByName(snapshot->children[i], snapshotName);
        if (ret != NULL)
            return ret;
    }
    return ret;
}

static virVBoxSnapshotConfHardDiskPtr
virVBoxSnapshotConfHardDiskById(virVBoxSnapshotConfHardDiskPtr disk,
                                const char *parentHardDiskId)
{
    size_t i = 0;
    virVBoxSnapshotConfHardDiskPtr ret = NULL;
    if (STREQ(disk->uuid, parentHardDiskId))
        return disk;
    for (i = 0; i < disk->nchildren; i++) {
        ret = virVBoxSnapshotConfHardDiskById(disk->children[i], parentHardDiskId);
        if (ret != NULL)
            return ret;
    }
    return ret;
}

static virVBoxSnapshotConfHardDiskPtr
virVBoxSnapshotConfHardDiskByLocation(virVBoxSnapshotConfHardDiskPtr disk,
                                      const char *parentLocation)
{
    size_t i = 0;
    virVBoxSnapshotConfHardDiskPtr ret = NULL;
    if (STREQ(disk->location, parentLocation))
        return disk;
    for (i = 0; i < disk->nchildren; i++) {
        ret = virVBoxSnapshotConfHardDiskByLocation(disk->children[i], parentLocation);
        if (ret != NULL)
            return ret;
    }
    return ret;
}

static xmlNodePtr
virVBoxSnapshotConfCreateHardDiskNode(virVBoxSnapshotConfHardDiskPtr hardDisk)
{
    int result = -1;
    size_t i = 0;
    char *uuid = NULL;
    xmlNodePtr ret = xmlNewNode(NULL, BAD_CAST "HardDisk");
    if (virAsprintf(&uuid, "{%s}", hardDisk->uuid) < 0)
        goto cleanup;

    if (xmlNewProp(ret, BAD_CAST "uuid", BAD_CAST uuid) == NULL)
        goto cleanup;
    if (xmlNewProp(ret, BAD_CAST "location", BAD_CAST hardDisk->location) == NULL)
        goto cleanup;
    if (xmlNewProp(ret, BAD_CAST "format", BAD_CAST hardDisk->format) == NULL)
        goto cleanup;
    if (hardDisk->type != NULL && xmlNewProp(ret, BAD_CAST "type", BAD_CAST hardDisk->type) == NULL)
        goto cleanup;

    for (i = 0; i < hardDisk->nchildren; i++) {
        xmlNodePtr child = virVBoxSnapshotConfCreateHardDiskNode(hardDisk->children[i]);
        if (child != NULL)
            xmlAddChild(ret, child);
    }

    result = 0;
 cleanup:
    if (result < 0) {
        xmlUnlinkNode(ret);
        xmlFreeNode(ret);
    }
    VIR_FREE(uuid);
    return ret;
}

static int
virVBoxSnapshotConfSerializeSnapshot(xmlNodePtr node,
                                     virVBoxSnapshotConfSnapshotPtr snapshot)
{
    int result = -1;
    size_t i = 0;
    xmlNodePtr descriptionNode = NULL;
    xmlNodePtr snapshotsNode = NULL;
    xmlNodePtr hardwareNode = NULL;
    xmlNodePtr storageControllerNode = NULL;
    xmlParserErrors parseError = XML_ERR_OK;
    char *uuid = NULL;
    char *timeStamp = NULL;

    char **firstRegex = NULL;
    int firstRegexResult = 0;
    char **secondRegex = NULL;
    int secondRegexResult = 0;

    if (virAsprintf(&uuid, "{%s}", snapshot->uuid) < 0)
        goto cleanup;

    if (xmlNewProp(node, BAD_CAST "uuid", BAD_CAST uuid) == NULL)
        goto cleanup;
    if (xmlNewProp(node, BAD_CAST "name", BAD_CAST snapshot->name) == NULL)
        goto cleanup;

    /* We change the date format from "yyyy-MM-dd hh:mm:ss.msec+timeZone"
     * to "yyyy-MM-ddThh:mm:ssZ"*/
    firstRegexResult = virStringSearch(snapshot->timeStamp,
                                       "([0-9]{4}-[0-9]{2}-[0-9]{2})",
                                       1,
                                       &firstRegex);
    secondRegexResult = virStringSearch(snapshot->timeStamp,
                                        "([0-9]{2}:[0-9]{2}:[0-9]{2})",
                                        1,
                                        &secondRegex);
    if (firstRegexResult < 1)
        goto cleanup;
    if (secondRegexResult < 1)
        goto cleanup;
    if (virAsprintf(&timeStamp, "%sT%sZ", firstRegex[0], secondRegex[0]) < 0)
        goto cleanup;

    if (xmlNewProp(node, BAD_CAST "timeStamp", BAD_CAST timeStamp) == NULL)
        goto cleanup;

    /*node description*/
    if (snapshot->description != NULL) {
        descriptionNode = xmlNewNode(NULL, BAD_CAST "Description");
        xmlNodeSetContent(descriptionNode, BAD_CAST snapshot->description);
        xmlAddChild(node, descriptionNode);
    }
    /*hardware*/
    parseError = xmlParseInNodeContext(node,
                                       snapshot->hardware,
                                       (int)strlen(snapshot->hardware),
                                       0,
                                       &hardwareNode);
    if (parseError != XML_ERR_OK) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to add the snapshot hardware"));
        goto cleanup;
    }
    xmlAddChild(node, hardwareNode);

    /*storageController*/
    if (xmlParseInNodeContext(node, snapshot->storageController,
                              (int)strlen(snapshot->storageController),
                              0,
                              &storageControllerNode) != XML_ERR_OK) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to add the snapshot storageController"));
        goto cleanup;
    }
    xmlAddChild(node, storageControllerNode);

    if (snapshot->nchildren > 0) {
        snapshotsNode = xmlNewNode(NULL, BAD_CAST "Snapshots");
        xmlAddChild(node, snapshotsNode);
        for (i = 0; i < snapshot->nchildren; i++) {
            xmlNodePtr child = xmlNewNode(NULL, BAD_CAST "Snapshot");
            xmlAddChild(snapshotsNode, child);
            if (virVBoxSnapshotConfSerializeSnapshot(child, snapshot->children[i]) < 0)
                goto cleanup;
        }
    }
    result = 0;

 cleanup:
    if (result < 0) {
        xmlFreeNode(descriptionNode);
        xmlUnlinkNode(snapshotsNode);
        xmlFreeNode(snapshotsNode);
    }
    virStringListFree(firstRegex);
    virStringListFree(secondRegex);
    VIR_FREE(uuid);
    VIR_FREE(timeStamp);
    return result;
}

static size_t
virVBoxSnapshotConfAllChildren(virVBoxSnapshotConfHardDiskPtr disk,
                               virVBoxSnapshotConfHardDiskPtr **list)
{
    size_t returnSize = 0;
    size_t tempSize = 0;
    virVBoxSnapshotConfHardDiskPtr *ret = NULL;
    virVBoxSnapshotConfHardDiskPtr *tempList = NULL;
    size_t i = 0;
    size_t j = 0;

    if (VIR_ALLOC_N(ret, 0) < 0)
        return 0;

    for (i = 0; i < disk->nchildren; i++) {
        tempSize = virVBoxSnapshotConfAllChildren(disk->children[i], &tempList);
        if (VIR_EXPAND_N(ret, returnSize, tempSize) < 0)
            goto error;

        for (j = 0; j < tempSize; j++)
            ret[returnSize - tempSize + j] = tempList[j];

        VIR_FREE(tempList);
    }

    if (VIR_EXPAND_N(ret, returnSize, 1) < 0)
        goto error;

    ret[returnSize - 1] = disk;
    *list = ret;
    return returnSize;

 error:
    VIR_FREE(tempList);
    VIR_FREE(ret);
    return 0;
}

void
virVboxSnapshotConfHardDiskFree(virVBoxSnapshotConfHardDiskPtr disk)
{
    size_t i = 0;

    if (!disk)
        return;

    VIR_FREE(disk->uuid);
    VIR_FREE(disk->location);
    VIR_FREE(disk->format);
    VIR_FREE(disk->type);
    for (i = 0; i < disk->nchildren; i++)
        virVboxSnapshotConfHardDiskFree(disk->children[i]);
    VIR_FREE(disk->children);
    VIR_FREE(disk);
}


void
virVBoxSnapshotConfMediaRegistryFree(virVBoxSnapshotConfMediaRegistryPtr mediaRegistry)
{
    size_t i = 0;

    if (!mediaRegistry)
        return;

    for (i = 0; i < mediaRegistry->ndisks; i++)
        virVboxSnapshotConfHardDiskFree(mediaRegistry->disks[i]);
    VIR_FREE(mediaRegistry->disks);
    for (i = 0; i < mediaRegistry->notherMedia; i++)
        VIR_FREE(mediaRegistry->otherMedia[i]);
    VIR_FREE(mediaRegistry->otherMedia);
    VIR_FREE(mediaRegistry);
}

void
virVBoxSnapshotConfSnapshotFree(virVBoxSnapshotConfSnapshotPtr snapshot)
{
    size_t i = 0;

    if (!snapshot)
        return;

    VIR_FREE(snapshot->uuid);
    VIR_FREE(snapshot->name);
    VIR_FREE(snapshot->timeStamp);
    VIR_FREE(snapshot->description);
    VIR_FREE(snapshot->hardware);
    VIR_FREE(snapshot->storageController);
    for (i = 0; i < snapshot->nchildren; i++)
        virVBoxSnapshotConfSnapshotFree(snapshot->children[i]);
    VIR_FREE(snapshot->children);
    VIR_FREE(snapshot);
}

void
virVBoxSnapshotConfMachineFree(virVBoxSnapshotConfMachinePtr machine)
{
    if (!machine)
        return;

    VIR_FREE(machine->uuid);
    VIR_FREE(machine->name);
    VIR_FREE(machine->currentSnapshot);
    VIR_FREE(machine->snapshotFolder);
    VIR_FREE(machine->lastStateChange);
    virVBoxSnapshotConfMediaRegistryFree(machine->mediaRegistry);
    VIR_FREE(machine->hardware);
    VIR_FREE(machine->extraData);
    virVBoxSnapshotConfSnapshotFree(machine->snapshot);
    VIR_FREE(machine->storageController);
    VIR_FREE(machine);
}

/*
 *vboxSnapshotLoadVboxFile: Create a vboxSnapshotXmlMachinePtr from a VirtualBoxl xml file.
 *return an initialized vboxSnapshotXmlMachinePtr on success
 *return NULL on failure
 *filePath must not be NULL.
 */
virVBoxSnapshotConfMachinePtr
virVBoxSnapshotConfLoadVboxFile(const char *filePath,
                                const char *machineLocation)
{
    int ret = -1;
    virVBoxSnapshotConfMachinePtr machineDescription = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr machineNode = NULL;
    xmlNodePtr cur = NULL;
    xmlXPathContextPtr xPathContext = NULL;
    char *currentStateModifiedString = NULL;

    char **searchResultTab = NULL;
    ssize_t searchResultSize = 0;
    char *currentSnapshotAttribute = NULL;

    if (filePath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Filepath is Null"));
        goto cleanup;
    }

    if (VIR_ALLOC(machineDescription) < 0)
        goto cleanup;

    xml = virXMLParse(filePath, NULL, NULL);
    if (xml == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to parse the xml"));
        goto cleanup;
    }
    if (!(xPathContext = xmlXPathNewContext(xml))) {
        virReportOOMError();
        goto cleanup;
    }
    if (xmlXPathRegisterNs(xPathContext,
                           BAD_CAST "vbox",
                           BAD_CAST "http://www.innotek.de/VirtualBox-settings") < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Failed to register xml namespace "
                         "'http://www.innotek.de/VirtualBox-settings'"));
        goto cleanup;
    }

    /*Retrieve MachineNode*/
    cur = xmlDocGetRootElement(xml);
    xPathContext->node = cur;
    machineNode = virXPathNode("./vbox:Machine", xPathContext);
    if (machineNode == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <VirtualBox> <Machine> node"));
        goto cleanup;
    }

    machineDescription->uuid = virXMLPropString(machineNode, "uuid");
    if (machineDescription->uuid == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> 'uuid' attribute"));
        goto cleanup;
    }
    machineDescription->name = virXMLPropString(machineNode, "name");
    if (machineDescription->name == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> 'name' attribute"));
        goto cleanup;
    }

    currentSnapshotAttribute = virXMLPropString(machineNode, "currentSnapshot");
    if (currentSnapshotAttribute != NULL) {
        /*we use virStringSearch because the uuid is between brackets*/
        searchResultSize = virStringSearch(currentSnapshotAttribute,
                                           VBOX_UUID_REGEX,
                                           1,
                                           &searchResultTab);
        if (searchResultSize != 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Cannot parse <Machine> 'currentSnapshot' attribute"));
            goto cleanup;
        }
        if (VIR_STRDUP(machineDescription->currentSnapshot, searchResultTab[0]) < 0)
            goto cleanup;
    }

    machineDescription->snapshotFolder = virXMLPropString(machineNode, "snapshotFolder");
    if (machineDescription->snapshotFolder == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> 'snapshotFolder' attribute"));
        goto cleanup;
    }

    currentStateModifiedString = virXMLPropString(machineNode, "currentStateModified");
    if (currentStateModifiedString != NULL && STREQ(currentStateModifiedString, "true")) {
        machineDescription->currentStateModified = 1;
    } else {
        machineDescription->currentStateModified = 0;
    }
    machineDescription->lastStateChange = virXMLPropString(machineNode, "lastStateChange");
    if (machineDescription->lastStateChange == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> 'lastStateChange' attribute"));
        goto cleanup;
    }

    xPathContext->node = machineNode;
    cur = virXPathNode("./vbox:Hardware", xPathContext);
    if (cur == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> <Hardware> node"));
        goto cleanup;
    }
    machineDescription->hardware = virXMLNodeToString(xml, cur);

    cur = virXPathNode("./vbox:ExtraData", xPathContext);
    if (cur)
        machineDescription->extraData = virXMLNodeToString(xml, cur);

    cur = virXPathNode("./vbox:StorageControllers", xPathContext);
    if (cur == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> <StorageControllers> node"));
        goto cleanup;
    }
    machineDescription->storageController = virXMLNodeToString(xml, cur);

    /*retrieve mediaRegistry*/
    cur = virXPathNode("./vbox:MediaRegistry", xPathContext);
    if (cur == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <Machine> <MediaRegistry> node"));
        goto cleanup;
    }
    machineDescription->mediaRegistry = virVBoxSnapshotConfRetrieveMediaRegistry(cur, xPathContext, machineLocation);
    if (machineDescription->mediaRegistry == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       ("Unable to create media registry"));
        goto cleanup;
    }

    /*retrieve snapshot*/
    xPathContext->node = machineNode;
    cur = virXPathNode("./vbox:Snapshot", xPathContext);
    if (cur != NULL) {
        machineDescription->snapshot = virVBoxSnapshotConfRetrieveSnapshot(cur, xPathContext);
        if (!machineDescription->snapshot)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    xmlXPathFreeContext(xPathContext);
    xmlFreeDoc(xml);

    VIR_FREE(currentStateModifiedString);
    VIR_FREE(currentSnapshotAttribute);
    virStringListFree(searchResultTab);
    if (ret < 0) {
        virVBoxSnapshotConfMachineFree(machineDescription);
        machineDescription = NULL;
    }
    return machineDescription;
}

/*
 *addSnapshotToXmlMachine: Add a vboxSnapshotXmlSnapshotPtr to a vboxSnapshotXmlMachinePtr.
 *If 'snapshotParentName' is not NULL, the snapshot whose name is 'snapshotParentName'
 *becomes the snapshot parent.
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfAddSnapshotToXmlMachine(virVBoxSnapshotConfSnapshotPtr snapshot,
                                           virVBoxSnapshotConfMachinePtr machine,
                                           const char *snapshotParentName)
{
    int ret = -1;
    virVBoxSnapshotConfSnapshotPtr parentSnapshot = NULL;

    if (snapshot == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Snapshot is Null"));
        goto cleanup;
    }
    if (machine == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Machine is Null"));
        goto cleanup;
    }

    /*If parent is NULL and the machine has no snapshot yet,
     *it means that the added snapshot is the first snapshot*/
    if (snapshotParentName == NULL) {
        if (machine->snapshot != NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to add this snapshot, there is already a snapshot "
                             "linked to the machine"));
            goto cleanup;
        }
        machine->snapshot = snapshot;
        ret = 0;
        goto cleanup;
    } else {
        if (machine->snapshot == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("The machine has no snapshot and it should have it"));
            goto cleanup;
        }
        parentSnapshot = virVBoxSnapshotConfSnapshotByName(machine->snapshot, snapshotParentName);
        if (parentSnapshot == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find the snapshot %s"), snapshotParentName);
            goto cleanup;
        }
        if (VIR_EXPAND_N(parentSnapshot->children, parentSnapshot->nchildren, 1) < 0)
            goto cleanup;

        parentSnapshot->children[parentSnapshot->nchildren - 1] = snapshot;
        ret = 0;
    }

 cleanup:
    return ret;
}

/*
 *addHardDisksToMediaRegistry: Add a vboxSnapshotXmlHardDiskPtr to the registry as a
 *child of the disk whose uuid is 'parentHardDiskId'.
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfAddHardDiskToMediaRegistry(virVBoxSnapshotConfHardDiskPtr hardDisk,
                                              virVBoxSnapshotConfMediaRegistryPtr mediaRegistry,
                                              const char *parentHardDiskId)
{
    int ret = -1;
    size_t i = 0;
    virVBoxSnapshotConfHardDiskPtr parentDisk = NULL;
    if (hardDisk == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Hard disk is null"));
        goto cleanup;
    }
    if (mediaRegistry == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Media Registry is null"));
        goto cleanup;
    }

    for (i = 0; i < mediaRegistry->ndisks; i++) {
        parentDisk = virVBoxSnapshotConfHardDiskById(mediaRegistry->disks[i], parentHardDiskId);
        if (parentDisk != NULL)
            break;
    }
    if (parentDisk == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get the parent disk"));
        goto cleanup;
    }
    /*Hard disk found*/
    if (VIR_EXPAND_N(parentDisk->children, parentDisk->nchildren, 1) < 0)
        goto cleanup;

    parentDisk->children[parentDisk->nchildren - 1] = hardDisk;
    if (hardDisk->parent == NULL)
        hardDisk->parent = parentDisk;
    ret = 0;

 cleanup:
    return ret;
}

/*
 *removeSnapshot: Remove the vboxSnapshotXmlSnapshotPtr whose name is 'snapshotName'
 *from a vboxSnapshotXmlMachinePtr.
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfRemoveSnapshot(virVBoxSnapshotConfMachinePtr machine,
                                  const char *snapshotName)
{
    int ret = -1;
    size_t i = 0;
    virVBoxSnapshotConfSnapshotPtr snapshot = NULL;
    virVBoxSnapshotConfSnapshotPtr parentSnapshot = NULL;
    if (machine == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("machine is null"));
        goto cleanup;
    }
    if (snapshotName == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("snapshotName is null"));
        goto cleanup;
    }
    if (machine->snapshot == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("the machine has no snapshot"));
        goto cleanup;
    }
    snapshot = virVBoxSnapshotConfSnapshotByName(machine->snapshot, snapshotName);
    if (snapshot == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find the snapshot with name %s"), snapshotName);
        goto cleanup;
    }
    if (snapshot->nchildren > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("This snapshot has children, "
                         "please delete theses snapshots before"));
        goto cleanup;
    }

    if (snapshot->parent == NULL) {
        if (machine->snapshot != snapshot) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("You are trying to remove a snapshot which does not exists"));
            goto cleanup;
        }
        machine->snapshot = NULL;
        virVBoxSnapshotConfSnapshotFree(snapshot);
        ret = 0;
        goto cleanup;
    }
    parentSnapshot = snapshot->parent;

    snapshot->parent = NULL;
    while (i < parentSnapshot->nchildren && parentSnapshot->children[i] != snapshot)
        ++i;
    if (VIR_DELETE_ELEMENT(parentSnapshot->children, i, parentSnapshot->nchildren) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}

/*
 *removeHardDisk: Remove the vboxSnapshotXmlHardDiskPtr whose uuid is 'uuid' from a
 *vboxSnapshotXmlMediaRegistryPtr. The hard disk must not have any children.
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfRemoveHardDisk(virVBoxSnapshotConfMediaRegistryPtr mediaRegistry,
                                  const char *uuid)
{
    int ret = -1;
    size_t i = 0;
    virVBoxSnapshotConfHardDiskPtr hardDisk = NULL;
    virVBoxSnapshotConfHardDiskPtr parentHardDisk = NULL;
    if (mediaRegistry == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Media registry is null"));
        goto cleanup;
    }
    if (uuid == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Uuid is null"));
        goto cleanup;
    }

    for (i = 0; i < mediaRegistry->ndisks; i++) {
        hardDisk = virVBoxSnapshotConfHardDiskById(mediaRegistry->disks[i], uuid);
        if (hardDisk != NULL)
            break;
    }
    if (hardDisk == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find the hard disk with uuid %s"), uuid);
        goto cleanup;
    }
    if (hardDisk->parent == NULL) {
        /* it means that the hard disk is in 'root' */
        for (i = 0; i < mediaRegistry->ndisks; i++) {
            if (hardDisk == mediaRegistry->disks[i])
                break;
        }
        if (VIR_DELETE_ELEMENT(mediaRegistry->disks, i, mediaRegistry->ndisks) < 0)
            goto cleanup;
        ret = 0;
        goto cleanup;
    }

    parentHardDisk = hardDisk->parent;
    i = 0;
    while (i < parentHardDisk->nchildren && parentHardDisk->children[i] != hardDisk)
        ++i;
    hardDisk->parent = NULL;
    if (VIR_DELETE_ELEMENT(parentHardDisk->children, i, parentHardDisk->nchildren) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    return ret;
}

/*vboxSnapshotSaveVboxFile: Create a VirtualBox XML file from a vboxSnapshotXmlMachinePtr.
 *The file is saved at 'filePath'.
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfSaveVboxFile(virVBoxSnapshotConfMachinePtr machine,
                                const char *filePath)
{
    int ret = -1;
    size_t i = 0;
    xmlDocPtr xml = NULL;
    xmlNodePtr mediaRegistryNode = NULL;
    xmlNodePtr snapshotNode = NULL;
    xmlNodePtr machineNode = NULL;
    xmlNodePtr hardDisksNode = NULL;
    xmlNodePtr cur = NULL;
    xmlParserErrors parseError = XML_ERR_OK;
    char *currentSnapshot = NULL;
    char *timeStamp = NULL;

    char **firstRegex = NULL;
    int firstRegexResult = 0;
    char **secondRegex = NULL;
    int secondRegexResult = 0;

    if (machine == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Machine is null"));
        goto cleanup;
    }
    if (filePath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Filepath is null"));
        goto cleanup;
    }
    xml = xmlNewDoc(BAD_CAST "1.0");
    if (!xml) {
        virReportOOMError();
        goto cleanup;
    }

    cur = xmlNewNode(NULL, BAD_CAST "VirtualBox");
    if (!cur) {
        virReportOOMError();
        goto cleanup;
    }

    if (!xmlNewProp(cur, BAD_CAST "version", BAD_CAST "1.12-linux")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }
    if (xmlNewProp(cur,
                   BAD_CAST "xmlns",
                   BAD_CAST "http://www.innotek.de/VirtualBox-settings") == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }

    xmlDocSetRootElement(xml, cur);

    cur = xmlNewDocComment(xml,
                           BAD_CAST "WARNING: THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE\n"
                           "OVERWRITTEN AND LOST.\n"
                           "Changes to this xml configuration should be made using Virtualbox\n"
                           "or other application using the libvirt API");
    if (!cur) {
        virReportOOMError();
        goto cleanup;
    }

    if (!xmlAddPrevSibling(xmlDocGetRootElement(xml), cur)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlAddPrevSibling"));
        goto cleanup;
    }

    machineNode = xmlNewNode(NULL, BAD_CAST "Machine");
    if (!machineNode) {
        virReportOOMError();
        goto cleanup;
    }

    if (!xmlNewProp(machineNode, BAD_CAST "uuid", BAD_CAST machine->uuid)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }
    if (!xmlNewProp(machineNode, BAD_CAST "name", BAD_CAST machine->name)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }

    if (machine->currentSnapshot != NULL) {
        if (virAsprintf(&currentSnapshot, "{%s}", machine->currentSnapshot) < 0)
            goto cleanup;
        if (!xmlNewProp(machineNode, BAD_CAST "currentSnapshot", BAD_CAST currentSnapshot)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Error in xmlNewProp"));
            goto cleanup;
        }
    }
    if (!xmlNewProp(machineNode, BAD_CAST "snapshotFolder", BAD_CAST machine->snapshotFolder)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }
    if (!xmlNewProp(machineNode, BAD_CAST "currentStateModified",
               BAD_CAST(machine->currentStateModified == 0 ? "false" : "true"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }
    if (!xmlNewProp(machineNode, BAD_CAST "OSType", BAD_CAST "Other")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }

    firstRegexResult = virStringSearch(machine->lastStateChange,
                                       "([0-9]{4}-[0-9]{2}-[0-9]{2})",
                                       1,
                                       &firstRegex);
    secondRegexResult = virStringSearch(machine->lastStateChange,
                                        "([0-9]{2}:[0-9]{2}:[0-9]{2})",
                                        1,
                                        &secondRegex);
    if (firstRegexResult < 1)
        goto cleanup;
    if (secondRegexResult < 1)
        goto cleanup;

    if (virAsprintf(&timeStamp, "%sT%sZ", firstRegex[0], secondRegex[0]) < 0)
        goto cleanup;
    if (!xmlNewProp(machineNode, BAD_CAST "lastStateChange", BAD_CAST timeStamp)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Error in xmlNewProp"));
        goto cleanup;
    }
    xmlAddChild(xmlDocGetRootElement(xml), machineNode);

    mediaRegistryNode = xmlNewNode(NULL, BAD_CAST "MediaRegistry");
    if (!mediaRegistryNode) {
        virReportOOMError();
        goto cleanup;
    }

    xmlAddChild(machineNode, mediaRegistryNode);
    for (i = 0; i < machine->mediaRegistry->notherMedia; i++) {
        parseError = xmlParseInNodeContext(mediaRegistryNode,
                              machine->mediaRegistry->otherMedia[i],
                              (int)strlen(machine->mediaRegistry->otherMedia[i]),
                              0,
                              &cur);
        if (parseError != XML_ERR_OK) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Unable to add media registry other media"));
            goto cleanup;
        }
        xmlAddChild(mediaRegistryNode, cur);
    }
    hardDisksNode = xmlNewNode(NULL, BAD_CAST "HardDisks");
    if (!hardDisksNode) {
        virReportOOMError();
        goto cleanup;
    }
    for (i = 0; i < machine->mediaRegistry->ndisks; i++) {
        xmlNodePtr child = virVBoxSnapshotConfCreateHardDiskNode(machine->mediaRegistry->disks[i]);
        if (child != NULL)
            xmlAddChild(hardDisksNode, child);
    }
    xmlAddChild(mediaRegistryNode, hardDisksNode);

    parseError = xmlParseInNodeContext(machineNode,
                                       machine->hardware,
                                       (int)strlen(machine->hardware),
                                       0,
                                       &cur);
    if (parseError != XML_ERR_OK) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to add hardware machine"));
        goto cleanup;
    }
    xmlAddChild(machineNode, cur);

    if (machine->extraData != NULL) {
        parseError = xmlParseInNodeContext(xmlDocGetRootElement(xml),
                                           machine->extraData,
                                           (int)strlen(machine->extraData),
                                           0,
                                           &cur);
        if (parseError != XML_ERR_OK) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Unable to add extra data"));
            goto cleanup;
        }
        xmlAddChild(machineNode, cur);
    }

    parseError = xmlParseInNodeContext(machineNode,
                                       machine->storageController,
                                       (int)strlen(machine->storageController),
                                       0,
                                       &cur);
    if (parseError != XML_ERR_OK) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to add storage controller"));
        goto cleanup;
    }
    xmlAddChild(machineNode, cur);

    if (machine->snapshot != NULL) {
        snapshotNode = xmlNewNode(NULL, BAD_CAST "Snapshot");
        xmlAddChild(machineNode, snapshotNode);
        if (virVBoxSnapshotConfSerializeSnapshot(snapshotNode, machine->snapshot) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Failed to serialize snapshot"));
            goto cleanup;
        }
    }

    if (xmlSaveFormatFileEnc(filePath, xml, "ISO-8859-1", 1) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to save the xml"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(currentSnapshot);
    VIR_FREE(timeStamp);

    xmlUnlinkNode(hardDisksNode);
    xmlFreeNode(hardDisksNode);

    xmlUnlinkNode(mediaRegistryNode);
    xmlFreeNode(mediaRegistryNode);

    xmlUnlinkNode(snapshotNode);
    xmlFreeNode(snapshotNode);

    xmlUnlinkNode(cur);
    xmlFreeNode(cur);

    xmlUnlinkNode(machineNode);
    xmlFreeNode(machineNode);

    xmlFreeDoc(xml);

    virStringListFree(firstRegex);
    virStringListFree(secondRegex);
    return ret;
}

/*
 *isCurrentSnapshot: Return 1 if 'snapshotName' corresponds to the
 *vboxSnapshotXmlMachinePtr's current snapshot, return 0 otherwise.
 */
int
virVBoxSnapshotConfIsCurrentSnapshot(virVBoxSnapshotConfMachinePtr machine,
                                     const char *snapshotName)
{
    virVBoxSnapshotConfSnapshotPtr snapshot = NULL;
    if (machine == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Machine is null"));
        goto cleanup;
    }
    if (snapshotName == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("snapshotName is null"));
        goto cleanup;
    }
    snapshot = virVBoxSnapshotConfSnapshotByName(machine->snapshot, snapshotName);
    if (snapshot == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("Unable to find the snapshot %s"), snapshotName);
        goto cleanup;
    }
    return STREQ(snapshot->uuid, machine->currentSnapshot);

 cleanup:
    return 0;
}

/*
 *getRWDisksPathsFromLibvirtXML: Parse a libvirt XML snapshot file, allocates and
 *fills a list of read-write disk paths.
 *return array length on success, -1 on failure.
 */
int
virVBoxSnapshotConfGetRWDisksPathsFromLibvirtXML(const char *filePath,
                                                 char ***rwDisksPath)
{
    int result = -1;
    size_t i = 0;
    char **ret = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr xPathContext = NULL;
    xmlNodePtr *nodes = NULL;
    int nodeSize = 0;
    *rwDisksPath = NULL;
    if (filePath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filePath is null"));
        goto cleanup;
    }
    xml = virXMLParse(filePath, NULL, NULL);
    if (xml == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to parse the xml"));
        goto cleanup;
    }
    if (!(xPathContext = xmlXPathNewContext(xml))) {
        virReportOOMError();
        goto cleanup;
    }
    xPathContext->node = xmlDocGetRootElement(xml);
    if ((nodeSize = virXPathNodeSet("/domainsnapshot/disks/disk",
                                    xPathContext, &nodes)) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(ret, nodeSize) < 0)
        goto cleanup;

    for (i = 0; i < nodeSize; i++) {
        xmlNodePtr node = nodes[i];
        xPathContext->node = node;
        xmlNodePtr sourceNode = virXPathNode("./source", xPathContext);
        if (sourceNode)
            ret[i] = virXMLPropString(sourceNode, "file");
    }
    result = 0;

 cleanup:
    xmlFreeDoc(xml);
    xmlXPathFreeContext(xPathContext);
    if (result < 0) {
        virStringListFree(ret);
        nodeSize = -1;
    } else {
        *rwDisksPath = ret;
    }
    VIR_FREE(nodes);
    return nodeSize;
}

/*
 *getRODisksPathsFromLibvirtXML: *Parse a libvirt XML snapshot file, allocates and fills
 *a list of read-only disk paths (the parents of the read-write disks).
 *return array length on success, -1 on failure.
 */
int
virVBoxSnapshotConfGetRODisksPathsFromLibvirtXML(const char *filePath,
                                                 char ***roDisksPath)
{
    int result = -1;
    size_t i = 0;
    char **ret = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr xPathContext = NULL;
    xmlNodePtr *nodes = NULL;
    int nodeSize = 0;
    if (filePath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("filePath is null"));
        goto cleanup;
    }
    xml = virXMLParse(filePath, NULL, NULL);
    if (xml == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Unable to parse the xml"));
        goto cleanup;
    }
    if (!(xPathContext = xmlXPathNewContext(xml))) {
        virReportOOMError();
        goto cleanup;
    }
    xPathContext->node = xmlDocGetRootElement(xml);
    if ((nodeSize = virXPathNodeSet("/domainsnapshot/domain/devices/disk",
                                    xPathContext,
                                    &nodes)) < 0)
        goto cleanup;
    if (VIR_ALLOC_N(ret, nodeSize) < 0)
        goto cleanup;

    for (i = 0; i < nodeSize; i++) {
        xmlNodePtr node = nodes[i];
        xPathContext->node = node;
        xmlNodePtr sourceNode = virXPathNode("./source", xPathContext);
        if (sourceNode)
            ret[i] = virXMLPropString(sourceNode, "file");
    }
    result = 0;

 cleanup:
    xmlFreeDoc(xml);
    xmlXPathFreeContext(xPathContext);
    if (result < 0) {
        virStringListFree(ret);
        nodeSize = -1;
    } else {
        *roDisksPath = ret;
    }
    VIR_FREE(nodes);
    return nodeSize;
}

/*
 *hardDiskUuidByLocation: Return the uuid of the hard disk whose location is 'location'
 *return a valid uuid, or NULL on failure
 */
const char *
virVBoxSnapshotConfHardDiskUuidByLocation(virVBoxSnapshotConfMachinePtr machine,
                                          const char *location)
{
    size_t i = 0;
    virVBoxSnapshotConfHardDiskPtr hardDisk = NULL;
    for (i = 0; i < machine->mediaRegistry->ndisks; i++) {
        hardDisk = virVBoxSnapshotConfHardDiskByLocation(machine->mediaRegistry->disks[i], location);
        if (hardDisk != NULL)
            break;
    }
    if (hardDisk == NULL)
        return NULL;
    return hardDisk->uuid;
}

/*Retreive the whole ancestry of the vboxSnapshotXmlHardDiskPtr whose location is
 *'location', and store them in a newly allocated list of vboxSnapshotXmlHardDiskPtr.
 *This list begins with the requested disk, and ends with the farthest ancestor.
 *return array length on success, -1 on failure.*/

size_t
virVBoxSnapshotConfDiskListToOpen(virVBoxSnapshotConfMachinePtr machine,
                                  virVBoxSnapshotConfHardDiskPtr **hardDiskToOpen,
                                  const char *location)
{
    size_t i = 0;
    size_t returnSize = 0;
    virVBoxSnapshotConfHardDiskPtr *ret = NULL;
    virVBoxSnapshotConfHardDiskPtr hardDisk = NULL;
    for (i = 0; i < machine->mediaRegistry->ndisks; i++) {
        hardDisk = virVBoxSnapshotConfHardDiskByLocation(machine->mediaRegistry->disks[i], location);
        if (hardDisk != NULL)
            break;
    }
    if (hardDisk == NULL)
        return 0;
    if (VIR_ALLOC_N(ret, 1) < 0)
        return 0;

    returnSize = 1;
    ret[returnSize - 1] = hardDisk;

    while (hardDisk->parent != NULL) {
        if (VIR_EXPAND_N(ret, returnSize, 1) < 0)
            return 0;
        ret[returnSize - 1] = hardDisk->parent;
        hardDisk = hardDisk->parent;
    }
    *hardDiskToOpen = ret;
    return returnSize;
}

/*
 *removeFakeDisks: Remove all fake disks from the machine's mediaRegistry
 *return 0 on success
 *return -1 on failure
 */
int
virVBoxSnapshotConfRemoveFakeDisks(virVBoxSnapshotConfMachinePtr machine)
{
    int ret = -1;
    size_t i = 0;
    size_t j = 0;
    size_t tempSize = 0;
    size_t diskSize = 0;
    virVBoxSnapshotConfHardDiskPtr *tempList = NULL;
    virVBoxSnapshotConfHardDiskPtr *diskList = NULL;

    if (VIR_ALLOC_N(diskList, 0) < 0)
        return -1;

    for (i = 0; i < machine->mediaRegistry->ndisks; i++) {
        tempSize = virVBoxSnapshotConfAllChildren(machine->mediaRegistry->disks[i], &tempList);
        if (VIR_EXPAND_N(diskList, diskSize, tempSize) < 0)
            goto cleanup;

        for (j = 0; j < tempSize; j++)
            diskList[diskSize - tempSize + j] = tempList[j];

        VIR_FREE(tempList);
    }

    for (i = 0; i < diskSize; i++) {
        if (strstr(diskList[i]->location, "fake") != NULL) {
            if (virVBoxSnapshotConfRemoveHardDisk(machine->mediaRegistry, diskList[i]->uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to remove hard disk %s from media registry"),
                               diskList[i]->location);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(diskList);
    VIR_FREE(tempList);

    return ret;
}

/*
 *diskIsInMediaRegistry: Check if the media registry contains the disk whose location is 'location'.
 *return 0 if the disk is not in the media registry
 *return 1 if the disk is in the media registry
 *return -1 on failure
 */
int
virVBoxSnapshotConfDiskIsInMediaRegistry(virVBoxSnapshotConfMachinePtr machine,
                                         const char *location)
{
    int ret = -1;
    size_t i = 0;
    size_t j = 0;
    size_t tempSize = 0;
    size_t diskSize = 0;
    virVBoxSnapshotConfHardDiskPtr *tempList = NULL;
    virVBoxSnapshotConfHardDiskPtr *diskList = NULL;

    if (VIR_ALLOC_N(diskList, 0) < 0)
        return -1;

    for (i = 0; i < machine->mediaRegistry->ndisks; i++) {
        tempSize = virVBoxSnapshotConfAllChildren(machine->mediaRegistry->disks[i], &tempList);
        if (VIR_EXPAND_N(diskList, diskSize, tempSize) < 0)
            goto cleanup;

        for (j = 0; j < tempSize; j++)
            diskList[diskSize - tempSize + j] = tempList[j];

        VIR_FREE(tempList);
    }

    for (i = 0; i < diskSize; i++) {
        if (STREQ(diskList[i]->location, location)) {
            ret = 1;
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(diskList);
    VIR_FREE(tempList);

    return ret;
}

/*
 *hardDisksPtrByLocation: Return a vboxSnapshotXmlHardDiskPtr whose location is 'location'
 */
virVBoxSnapshotConfHardDiskPtr
virVBoxSnapshotConfHardDiskPtrByLocation(virVBoxSnapshotConfMachinePtr machine,
                                         const char *location)
{
    int it = 0;
    virVBoxSnapshotConfHardDiskPtr disk = NULL;
    for (it = 0; it < machine->mediaRegistry->ndisks; it++) {
        disk = virVBoxSnapshotConfHardDiskByLocation(machine->mediaRegistry->disks[it], location);
        if (disk != NULL)
            break;
    }
    return disk;
}
