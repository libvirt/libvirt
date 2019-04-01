#!/usr/bin/env python3

import os
import sys
import json
import xmltodict

def cpuidIsSet(cpuid, feature):
    in_eax = feature["in_eax"]
    in_ecx = feature["in_ecx"]
    eax = feature["eax"]
    ebx = feature["ebx"]
    ecx = feature["ecx"]
    edx = feature["edx"]

    if in_eax not in cpuid or in_ecx not in cpuid[in_eax]:
        return False
    else:
        leaf = cpuid[in_eax][in_ecx]
        return ((eax > 0 and leaf["eax"] & eax > 0) or
                (ebx > 0 and leaf["ebx"] & ebx > 0) or
                (ecx > 0 and leaf["ecx"] & ecx > 0) or
                (edx > 0 and leaf["edx"] & edx > 0))


def cpuidAdd(cpuid, feature):
    if feature["in_eax"] not in cpuid:
        cpuid[feature["in_eax"]] = {}
    leaf = cpuid[feature["in_eax"]]

    if feature["in_ecx"] not in leaf:
        leaf[feature["in_ecx"]] = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0}
    leaf = leaf[feature["in_ecx"]]

    for reg in ["eax", "ebx", "ecx", "edx"]:
        leaf[reg] |= feature[reg]


def parseQemu(path, features):
    cpuid = {}
    with open(path, "r") as f:
        data, pos = json.JSONDecoder().raw_decode(f.read())

    for (prop, val) in data["return"]["model"]["props"].items():
        if val and prop in features:
            cpuidAdd(cpuid, features[prop])

    return cpuid


def parseCpuid(path):
    cpuid = {}
    with open(path, "rb") as f:
        data = xmltodict.parse(f)

    for leaf in data["cpudata"]["cpuid"]:
        feature = {}
        feature["in_eax"] = int(leaf["@eax_in"], 0)
        feature["in_ecx"] = int(leaf["@ecx_in"], 0)
        for reg in ["eax", "ebx", "ecx", "edx"]:
            feature[reg] = int(leaf["@" + reg], 0)

        cpuidAdd(cpuid, feature)

    return cpuid


def parseFeature(data):
    cpuid = {}
    for reg in ["in_eax", "in_ecx", "eax", "ebx", "ecx", "edx"]:
        if reg.startswith("in_"):
            attr = "@%s_in" % reg[3:]
        else:
            attr = "@%s" % reg

        if attr in data:
            cpuid[reg] = int(data[attr], 0)
        else:
            cpuid[reg] = 0

    return cpuid


def parseMap():
    path = os.path.dirname(sys.argv[0])
    path = os.path.join(path, "..", "..", "src", "cpu_map", "x86_features.xml")
    with open(path, "rb") as f:
        data = xmltodict.parse(f)

    cpuMap = {}
    for feature in data["cpus"]["feature"]:
        if "cpuid" in feature:
            cpuMap[feature["@name"]] = parseFeature(feature["cpuid"])

    return cpuMap


def formatCpuid(cpuid, path, comment):
    print(path)
    with open(path, "w") as f:
        f.write("<!-- " + comment + " -->\n")
        f.write("<cpudata arch='x86'>\n")
        for in_eax in sorted(cpuid.keys()):
            for in_ecx in sorted(cpuid[in_eax].keys()):
                leaf = cpuid[in_eax][in_ecx]
                line = ("  <cpuid eax_in='0x%08x' ecx_in='0x%02x' "
                        "eax='0x%08x' ebx='0x%08x' "
                        "ecx='0x%08x' edx='0x%08x'/>\n")
                f.write(line % (
                        in_eax, in_ecx,
                        leaf["eax"], leaf["ebx"], leaf["ecx"], leaf["edx"]))
        f.write("</cpudata>\n")


def diff(cpuMap, path):
    base = path.replace(".json", "")
    jsonFile = path
    cpuidFile = base + ".xml"
    enabledFile = base + "-enabled.xml"
    disabledFile = base + "-disabled.xml"

    cpuid = parseCpuid(cpuidFile)
    qemu = parseQemu(jsonFile, cpuMap)

    enabled = {}
    disabled = {}
    for feature in cpuMap.values():
        if cpuidIsSet(qemu, feature):
            cpuidAdd(enabled, feature)
        elif cpuidIsSet(cpuid, feature):
            cpuidAdd(disabled, feature)

    formatCpuid(enabled, enabledFile, "Features enabled by QEMU")
    formatCpuid(disabled, disabledFile, "Features disabled by QEMU")


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
