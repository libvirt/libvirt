#!/usr/bin/env python3

import os
import sys
import json
import xmltodict


def checkCPUIDFeature(cpuData, feature):
    eax_in = feature["eax_in"]
    ecx_in = feature["ecx_in"]
    eax = feature["eax"]
    ebx = feature["ebx"]
    ecx = feature["ecx"]
    edx = feature["edx"]

    if "cpuid" not in cpuData:
        return False

    cpuid = cpuData["cpuid"]
    if eax_in not in cpuid or ecx_in not in cpuid[eax_in]:
        return False

    leaf = cpuid[eax_in][ecx_in]
    return ((eax > 0 and leaf["eax"] & eax == eax) or
            (ebx > 0 and leaf["ebx"] & ebx == ebx) or
            (ecx > 0 and leaf["ecx"] & ecx == ecx) or
            (edx > 0 and leaf["edx"] & edx == edx))


def checkMSRFeature(cpuData, feature):
    index = feature["index"]
    edx = feature["edx"]
    eax = feature["eax"]

    if "msr" not in cpuData:
        return False

    msr = cpuData["msr"]
    if index not in msr:
        return False

    msr = msr[index]
    return ((edx > 0 and msr["edx"] & edx == edx) or
            (eax > 0 and msr["eax"] & eax == eax))


def checkFeature(cpuData, feature):
    if feature["type"] == "cpuid":
        return checkCPUIDFeature(cpuData, feature)

    if feature["type"] == "msr":
        return checkMSRFeature(cpuData, feature)


def addCPUIDFeature(cpuData, feature):
    if "cpuid" not in cpuData:
        cpuData["cpuid"] = {}
    cpuid = cpuData["cpuid"]

    if feature["eax_in"] not in cpuid:
        cpuid[feature["eax_in"]] = {}
    leaf = cpuid[feature["eax_in"]]

    if feature["ecx_in"] not in leaf:
        leaf[feature["ecx_in"]] = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0}
    leaf = leaf[feature["ecx_in"]]

    for reg in ["eax", "ebx", "ecx", "edx"]:
        leaf[reg] |= feature[reg]


def addMSRFeature(cpuData, feature):
    if "msr" not in cpuData:
        cpuData["msr"] = {}
    msr = cpuData["msr"]

    if feature["index"] not in msr:
        msr[feature["index"]] = {"edx": 0, "eax": 0}
    msr = msr[feature["index"]]

    for reg in ["edx", "eax"]:
        msr[reg] |= feature[reg]


def addFeature(cpuData, feature):
    if feature["type"] == "cpuid":
        addCPUIDFeature(cpuData, feature)
    elif feature["type"] == "msr":
        addMSRFeature(cpuData, feature)


def parseQemu(path, features):
    cpuData = {}
    with open(path, "r") as f:
        data, pos = json.JSONDecoder().raw_decode(f.read())

    for (prop, val) in data["return"]["model"]["props"].items():
        if val and prop in features:
            addFeature(cpuData, features[prop])

    return cpuData


def parseCPUData(path):
    cpuData = {}
    with open(path, "rb") as f:
        data = xmltodict.parse(f)

    for leaf in data["cpudata"]["cpuid"]:
        feature = {"type": "cpuid"}
        feature["eax_in"] = int(leaf["@eax_in"], 0)
        feature["ecx_in"] = int(leaf["@ecx_in"], 0)
        for reg in ["eax", "ebx", "ecx", "edx"]:
            feature[reg] = int(leaf["@" + reg], 0)

        addFeature(cpuData, feature)

    if "msr" in data["cpudata"]:
        if not isinstance(data["cpudata"]["msr"], list):
            data["cpudata"]["msr"] = [data["cpudata"]["msr"]]

        for msr in data["cpudata"]["msr"]:
            feature = {"type": "msr"}
            feature["index"] = int(msr["@index"], 0)
            feature["edx"] = int(msr["@edx"], 0)
            feature["eax"] = int(msr["@eax"], 0)

            addFeature(cpuData, feature)

    return cpuData


def parseMapFeature(fType, data):
    ret = {"type": fType}

    if fType == "cpuid":
        fields = ["eax_in", "ecx_in", "eax", "ebx", "ecx", "edx"]
    elif fType == "msr":
        fields = ["index", "edx", "eax"]

    for field in fields:
        attr = "@%s" % field
        if attr in data:
            ret[field] = int(data[attr], 0)
        else:
            ret[field] = 0

    return ret


def parseMap():
    path = os.path.dirname(sys.argv[0])
    path = os.path.join(path, "..", "..", "src", "cpu_map", "x86_features.xml")
    with open(path, "rb") as f:
        data = xmltodict.parse(f)

    cpuMap = {}
    for feature in data["cpus"]["feature"]:
        for fType in ["cpuid", "msr"]:
            if fType in feature:
                cpuMap[feature["@name"]] = parseMapFeature(fType, feature[fType])

    return cpuMap


def formatCPUData(cpuData, path, comment):
    print(path)
    with open(path, "w") as f:
        f.write("<!-- " + comment + " -->\n")
        f.write("<cpudata arch='x86'>\n")

        cpuid = cpuData["cpuid"]
        for eax_in in sorted(cpuid.keys()):
            for ecx_in in sorted(cpuid[eax_in].keys()):
                leaf = cpuid[eax_in][ecx_in]
                line = ("  <cpuid eax_in='0x%08x' ecx_in='0x%02x' "
                        "eax='0x%08x' ebx='0x%08x' "
                        "ecx='0x%08x' edx='0x%08x'/>\n")
                f.write(line % (
                        eax_in, ecx_in,
                        leaf["eax"], leaf["ebx"], leaf["ecx"], leaf["edx"]))

        if "msr" in cpuData:
            msr = cpuData["msr"]
            for index in sorted(msr.keys()):
                f.write("  <msr index='0x%x' edx='0x%08x' eax='0x%08x'/>\n" %
                        (index, msr[index]['edx'], msr[index]['eax']))

        f.write("</cpudata>\n")


def diff(cpuMap, path):
    base = path.replace(".json", "")
    jsonFile = path
    cpuDataFile = base + ".xml"
    enabledFile = base + "-enabled.xml"
    disabledFile = base + "-disabled.xml"

    cpuData = parseCPUData(cpuDataFile)
    qemu = parseQemu(jsonFile, cpuMap)

    enabled = {"cpuid": {}}
    disabled = {"cpuid": {}}
    for feature in cpuMap.values():
        if checkFeature(qemu, feature):
            addFeature(enabled, feature)
        elif checkFeature(cpuData, feature):
            addFeature(disabled, feature)

    formatCPUData(enabled, enabledFile, "Features enabled by QEMU")
    formatCPUData(disabled, disabledFile, "Features disabled by QEMU")


if len(sys.argv) < 3:
    print("Usage: %s diff json_file..." % sys.argv[0])
    sys.exit(1)

action = sys.argv[1]
args = sys.argv[2:]

if action == "diff":
    cpuMap = parseMap()
    for path in args:
        diff(cpuMap, path)
else:
    print("Unknown action: %s" % action)
    sys.exit(1)
