#!/usr/bin/env python3

import argparse
import fcntl
import json
import os
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree

_KEYS = {
    "cpuid": ["eax_in", "ecx_in"],
    "msr": ["index"],
}

_REGS = {
    "cpuid": ["eax", "ebx", "ecx", "edx"],
    "msr": ["eax", "edx"],
}


def gather_name(args):
    if args.name:
        return args.name

    with open("/proc/cpuinfo", "rt") as f:
        for line in f.readlines():
            if line.startswith("model name"):
                return line.split(":", 2)[1].strip()

    exit("Error: '/proc/cpuinfo' does not contain a model name.\n"
         "Use '--model' to set a model name.")


def gather_cpuid_leaves_cpuid(output):
    leave_pattern = re.compile(
        "^\\s*"
        "(0x[0-9a-f]+)\\s*"
        "(0x[0-9a-f]+):\\s*"
        "eax=(0x[0-9a-f]+)\\s*"
        "ebx=(0x[0-9a-f]+)\\s*"
        "ecx=(0x[0-9a-f]+)\\s*"
        "edx=(0x[0-9a-f]+)\\s*$")

    for line in output.split("\n"):
        match = leave_pattern.match(line)
        if not match:
            continue
        yield {
            "eax_in": int(match.group(1), 0),
            "ecx_in": int(match.group(2), 0),
            "eax": int(match.group(3), 0),
            "ebx": int(match.group(4), 0),
            "ecx": int(match.group(5), 0),
            "edx": int(match.group(6), 0)}


def gather_cpuid_leaves_kcpuid(output):
    leave_pattern = re.compile(
        "^(0x[0-9a-f]+): "
        "EAX=(0x[0-9a-f]+), "
        "EBX=(0x[0-9a-f]+), "
        "ECX=(0x[0-9a-f]+), "
        "EDX=(0x[0-9a-f]+)$")
    branch_pattern_head = re.compile(
        "^(0x[0-9a-f]+): "
        "subleafs:$")
    branch_pattern_body = re.compile(
        "^\\s*([0-9]+): "
        "EAX=(0x[0-9a-f]+), "
        "EBX=(0x[0-9a-f]+), "
        "ECX=(0x[0-9a-f]+), "
        "EDX=(0x[0-9a-f]+)$")

    regs = list()
    eax_in = 0
    for line in output.split("\n"):
        match = branch_pattern_head.match(line)
        if match:
            eax_in = int(match.group(1), 0)
            continue
        match = branch_pattern_body.match(line)
        if match:
            regs.append({
                "eax_in": eax_in,
                "ecx_in": int(match.group(1), 0),
                "eax": int(match.group(2), 0),
                "ebx": int(match.group(3), 0),
                "ecx": int(match.group(4), 0),
                "edx": int(match.group(5), 0)})
            continue
        match = leave_pattern.match(line)
        if match:
            regs.append({
                "eax_in": int(match.group(1), 0),
                "ecx_in": 0,
                "eax": int(match.group(2), 0),
                "ebx": int(match.group(3), 0),
                "ecx": int(match.group(4), 0),
                "edx": int(match.group(5), 0)})
            continue
    return regs


def gather_cpuid_leaves(args):
    def mask(regs, eax_in, ecx_in, eax_mask, ebx_mask, ecx_mask, edx_mask):
        if eax_in != regs["eax_in"]:
            return
        if ecx_in != regs["ecx_in"] and ecx_in is not None:
            return
        regs["eax"] &= eax_mask
        regs["ebx"] &= ebx_mask
        regs["ecx"] &= ecx_mask
        regs["edx"] &= edx_mask

    cpuid = args.path_to_cpuid or "cpuid"
    try:
        output = subprocess.check_output(
            [cpuid, "-r" if "kcpuid" in cpuid else "-1r"],
            universal_newlines=True)
    except FileNotFoundError as e:
        exit("Error: '{}' not found.\n'cpuid' can be usually found in a "
             "package named identically. If your distro does not provide such "
             "package, you can find the sources or binary packages at "
             "'http://www.etallen.com/cpuid.html'.".format(e.filename))

    if "=====" in output:
        reglist = gather_cpuid_leaves_kcpuid(output)
    else:
        reglist = gather_cpuid_leaves_cpuid(output)

    for regs in reglist:
        # local apic id. Pretend to always run on logical processor #0.
        mask(regs, 0x01, 0x00, 0xffffffff, 0x00ffffff, 0xffffffff, 0xffffffff)
        mask(regs, 0x0b, None, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000)
        mask(regs, 0x1f, None, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000)

        yield regs


def gather_msr():
    msrs = dict()
    addresses = [
        0x10a,  # IA32_ARCH_CAPABILITIES_MSR
        0xcf,   # IA32_CORE_CAPABILITY_MSR
    ]
    KVM_GET_MSRS = 0xc008ae88

    try:
        with open("/dev/cpu/0/msr", "rb") as f:
            for addr in addresses:
                f.seek(addr)
                buf = f.read(8)
                msrs[addr] = struct.unpack("=Q", buf)[0]
            return "", msrs
    except IOError as e:
        print("Warning: {}".format(e), file=sys.stderr)

    try:
        with open("/dev/kvm", "rb") as f:
            for addr in addresses:
                bufIn = struct.pack("=LLLLQ", 1, 0, addr, 0, 0)
                bufOut = fcntl.ioctl(f, KVM_GET_MSRS, bufIn)
                msrs[addr] = struct.unpack("=LLLLQ", bufOut)[4]
            return " via KVM", msrs
    except IOError as e:
        print("Warning: {}".format(e), file=sys.stderr)

    return None, {}


def call_qemu(qemu, qmp_cmds):
    cmd = [
        qemu,
        "-machine", "accel=kvm",
        "-cpu", "host",
        "-nodefaults",
        "-nographic",
        "-qmp", "stdio"]

    stdin = list()
    stdin.append("{\"execute\": \"qmp_capabilities\"}")
    stdin.extend([json.dumps(o) for o in qmp_cmds])
    stdin.append("{\"execute\": \"quit\"}")

    try:
        output = subprocess.check_output(
            cmd,
            universal_newlines=True,
            input="\n".join(stdin))
    except subprocess.CalledProcessError:
        exit("Error: Non-zero exit code from '{}'.".format(qemu))
    except FileNotFoundError:
        exit("Error: File not found: '{}'.".format(qemu))

    for line in output.split("\n"):
        if not line:
            continue
        response = json.loads(line)
        if "return" in response and not response["return"]:
            continue
        if response.get("event") == "SHUTDOWN":
            continue
        yield response


def gather_model(args):
    output = call_qemu(args.path_to_qemu, [
        {
            "execute": "query-cpu-model-expansion",
            "arguments":
            {
                "type": "static",
                "model": {"name": "host"}
            },
            "id": "model-expansion"
        }])

    version = 0, 0
    static_model = None
    for o in output:
        if o.get("id") == "model-expansion":
            static_model = o["return"]["model"]
        if "QMP" in o:
            version = o["QMP"]["version"]["qemu"]
            version = version["major"], version["minor"]

    if static_model:
        if version[0] > 6 or (version[0] == 6 and version[1] >= 1):
            static_model["props"]["hv-passthrough"] = True

        return call_qemu(args.path_to_qemu, [
            {
                "execute": "query-cpu-model-expansion",
                "arguments":
                {
                    "type": "full",
                    "model": static_model
                },
                "id": "model-expansion"
            },
            {
                "execute": "query-cpu-definitions",
                "id": "definitions"
            }
        ])
    else:
        return call_qemu(args.path_to_qemu, [
            {
                "execute": "qom-get",
                "arguments":
                {
                    "path": "/machine/unattached/device[0]",
                    "property": "feature-words"
                },
                "id": "feature-words"
            },
            {
                "execute": "qom-get",
                "arguments":
                {
                    "path": "/machine/unattached/device[0]",
                    "property": "family"
                },
                "id": "family"
            },
            {
                "execute": "qom-get",
                "arguments":
                {
                    "path": "/machine/unattached/device[0]",
                    "property": "model"
                },
                "id": "model"
            },
            {
                "execute": "qom-get",
                "arguments":
                {
                    "path": "/machine/unattached/device[0]",
                    "property": "stepping"
                },
                "id": "stepping"
            },
            {
                "execute": "qom-get",
                "arguments":
                {
                    "path": "/machine/unattached/device[0]",
                    "property": "model-id"
                },
                "id": "model-id"
            },
            {
                "execute": "query-cpu-definitions",
                "id": "definitions"
            }
        ])


def gather(args):
    result = dict()
    result["name"] = gather_name(args)
    result["leaves"] = list(gather_cpuid_leaves(args))
    result["via"], result["msr"] = gather_msr()
    result["model"] = list(gather_model(args))
    return result


def parse_filename(data):
    filename = data["name"].strip()
    filename = re.sub("[ -]+ +", " ", filename)
    filename = re.sub("\\(([Rr]|[Tt][Mm])\\)", "", filename)
    filename = re.sub(".*(Intel|AMD) ", "", filename)
    filename = re.sub(" (Duo|Quad|II X[0-9]+)", " ", filename)
    filename = re.sub(" (CPU|[Pp]rocessor)", "", filename)
    filename = re.sub(" @.*", "", filename)
    filename = re.sub(" APU .*", "", filename)
    filename = re.sub(" SE$", "", filename)
    filename = re.sub(" ", "-", filename)
    return "x86_64-cpuid-{}".format(filename)


def output_xml(data, filename):
    leave_template = \
        "  <cpuid" \
        " eax_in='0x{0[eax_in]:08x}'" \
        " ecx_in='0x{0[ecx_in]:02x}'" \
        " eax='0x{0[eax]:08x}'" \
        " ebx='0x{0[ebx]:08x}'" \
        " ecx='0x{0[ecx]:08x}'" \
        " edx='0x{0[edx]:08x}'" \
        "/>\n"

    msr_template = "  <msr index='0x{:x}' edx='0x{:08x}' eax='0x{:08x}'/>\n"

    print(filename)
    with open(filename, "wt") as f:
        f.write("<!-- {} -->\n".format(data["name"]))
        f.write("<cpudata arch='x86'>\n")
        for leave in data["leaves"]:
            f.write(leave_template.format(leave))
        for key, value in sorted(data["msr"].items()):
            f.write(msr_template.format(
                int(key),
                0xffffffff & (value >> 32),
                0xffffffff & (value >> 0)))
        f.write("</cpudata>\n")


def output_json(data, filename):
    replies = list()
    for reply in data["model"]:
        if "QMP" in reply:
            continue
        if "timestamp" in reply:
            continue
        if "return" in reply and not reply["return"]:
            continue
        replies.append(reply)

    if not replies:
        return

    if "model-expansion" not in [reply.get("id") for reply in replies]:
        exit(
            "Error: Missing query-cpu-model-expansion reply in "
            "{}".format(filename))

    print(filename)
    with open(filename, "wt") as f:
        for reply in replies:
            if reply is not replies[0]:
                f.write("\n")
            json.dump(reply, f, indent=2)
            f.write("\n")


def parse(args, data):
    filename = parse_filename(data)
    filename_xml = "{}.xml".format(filename)
    filename_json = "{}.json".format(filename)

    output_xml(data, filename_xml)
    output_json(data, filename_json)

    if not os.path.isfile(filename_json):
        return
    if os.path.getsize(filename_json) == 0:
        return

    args.json_files = getattr(args, "json_files", list()) + [filename_json]


def checkFeature(cpuData, feature):
    for key in ["type"] + _KEYS.get(feature["type"], list()):
        if feature[key] not in cpuData:
            return False
        cpuData = cpuData[feature[key]]

    for reg in _REGS.get(feature["type"], list()):
        if feature[reg] > 0 and feature[reg] == feature[reg] & cpuData[reg]:
            return True
    return False


def addFeature(cpuData, feature):
    for key in ["type"] + _KEYS.get(feature["type"], list()):
        if feature[key] not in cpuData:
            cpuData[feature[key]] = dict()
        cpuData = cpuData[feature[key]]

    for reg in _REGS.get(feature["type"], list()):
        cpuData[reg] = cpuData.get(reg, 0) | feature[reg]


def parseQemu(path, features):
    cpuData = {}
    with open(path, "r") as f:
        data, pos = json.JSONDecoder().raw_decode(f.read())

    for (prop, val) in data["return"]["model"]["props"].items():
        if val and prop in features:
            addFeature(cpuData, features[prop])

    return cpuData


def parseCPUData(path):
    cpuData = dict()
    for f in xml.etree.ElementTree.parse(path).getroot():
        if f.tag not in ("cpuid", "msr"):
            continue

        feature = {"type": f.tag}
        for reg in _KEYS[f.tag] + _REGS[f.tag]:
            feature[reg] = int(f.attrib.get(reg, "0"), 0)
        addFeature(cpuData, feature)
    return cpuData


def parseMap():
    path = os.path.dirname(sys.argv[0])
    path = os.path.join(path, "..", "..", "src", "cpu_map", "x86_features.xml")

    cpuMap = dict()
    for f in xml.etree.ElementTree.parse(path).getroot().iter("feature"):
        data = f.find("cpuid")
        if data is None:
            data = f.find("msr")
        if data is None:
            continue

        feature = {"type": data.tag}
        for reg in _KEYS[data.tag] + _REGS[data.tag]:
            feature[reg] = int(data.attrib.get(reg, "0"), 0)
        cpuMap[f.attrib["name"]] = feature
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


def diff(args):
    cpuMap = parseMap()

    for jsonFile in args.json_files:
        cpuDataFile = jsonFile.replace(".json", ".xml")
        enabledFile = jsonFile.replace(".json", "-enabled.xml")
        disabledFile = jsonFile.replace(".json", "-disabled.xml")

        cpuData = parseCPUData(cpuDataFile)
        qemu = parseQemu(jsonFile, cpuMap)

        enabled = dict()
        disabled = dict()
        for feature in cpuMap.values():
            if checkFeature(qemu, feature):
                addFeature(enabled, feature)
            elif checkFeature(cpuData, feature):
                addFeature(disabled, feature)

        formatCPUData(enabled, enabledFile, "Features enabled by QEMU")
        formatCPUData(disabled, disabledFile, "Features disabled by QEMU")


def main():
    parser = argparse.ArgumentParser(description="Gather cpu test data")
    parser.add_argument(
        "--name",
        help="CPU model name. "
        "If unset, model name is read from '/proc/cpuinfo'.")
    parser.add_argument(
        "--path-to-cpuid",
        metavar="PATH",
        help="Path to 'cpuid' utility. "
        "If unset, the first executable 'cpuid' in $PATH is used.")
    parser.add_argument(
        "--path-to-qemu",
        metavar="PATH",
        help="Path to qemu. "
        "If unset, will try '/usr/bin/qemu-system-x86_64', "
        "'/usr/bin/qemu-kvm', and '/usr/libexec/qemu-kvm'.")
    subparsers = parser.add_subparsers(dest="action")
    subparsers.add_parser(
        "gather",
        help="Acquire data on target system and outputs to stdout. "
        "This is the default. ")
    subparsers.add_parser(
        "parse",
        help="Reads data from stdin and parses data for libvirt use.")
    subparsers.add_parser(
        "full",
        help="Equivalent to `cpu-data.py gather | cpu-data.py parse`.")
    diffparser = subparsers.add_parser(
        "diff",
        help="Diff json description of CPU model against known features.")
    diffparser.add_argument(
        "json_files",
        nargs="+",
        metavar="FILE",
        type=os.path.realpath,
        help="Path to one or more json CPU model descriptions.")

    args = parser.parse_args()

    if not args.action:
        args.action = "gather"

    if not args.path_to_qemu:
        args.path_to_qemu = "qemu-system-x86_64"
        search = [
            "/usr/bin/qemu-system-x86_64",
            "/usr/bin/qemu-kvm",
            "/usr/libexec/qemu-kvm"]
        for f in search:
            if os.path.isfile(f):
                args.path_to_qemu = f

    if args.action in ["gather", "full"]:
        data = gather(args)
        if args.action == "gather":
            json.dump(data, sys.stdout, indent=2)

    if args.action in ["parse", "full"]:
        if args.action == "parse":
            data = json.load(sys.stdin)
        parse(args, data)

    if "json_files" in args:
        diff(args)


if __name__ == "__main__":
    main()
