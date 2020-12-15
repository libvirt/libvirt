#!/usr/bin/env python3

import argparse
import fcntl
import json
import os
import re
import struct
import subprocess
import sys


def gather_name(args):
    if args.name:
        return args.name

    with open("/proc/cpuinfo", "rt") as f:
        for line in f.readlines():
            if line.startswith("model name"):
                return line.split(":", 2)[1].strip()

    exit("Error: '/proc/cpuinfo' does not contain a model name.\n"
         "Use '--model' to set a model name.")


def gather_cpuid_leaves(args):
    cpuid = args.path_to_cpuid or "cpuid"
    try:
        output = subprocess.check_output(
            [cpuid, "-1r"],
            universal_newlines=True)
    except FileNotFoundError as e:
        exit("Error: '{}' not found.\n'cpuid' can be usually found in a "
             "package named identically. If your distro does not provide such "
             "package, you can find the sources or binary packages at "
             "'http://www.etallen.com/cpuid.html'.".format(e.filename))

    for line in output.split("\n"):
        if not line:
            continue
        if line == "CPU:":
            continue
        yield line.strip()


def gather_msr():
    IA32_ARCH_CAPABILITIES_MSR = 0x10a
    KVM_GET_MSRS = 0xc008ae88

    try:
        with open("/dev/cpu/0/msr", "rb") as f:
            f.seek(IA32_ARCH_CAPABILITIES_MSR)
            buf = f.read(8)
            msr = struct.unpack("=Q", buf)[0]
            return "", {IA32_ARCH_CAPABILITIES_MSR: msr}
    except IOError as e:
        print("Warning: {}".format(e), file=sys.stderr)

    try:
        bufIn = struct.pack("=LLLLQ", 1, 0, IA32_ARCH_CAPABILITIES_MSR, 0, 0)
        with open("/dev/kvm", "rb") as f:
            bufOut = fcntl.ioctl(f, KVM_GET_MSRS, bufIn)
            msr = struct.unpack("=LLLLQ", bufOut)[4]
            return " via KVM", {IA32_ARCH_CAPABILITIES_MSR: msr}
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

    static_model = None
    for o in output:
        if o.get("id") == "model-expansion":
            static_model = o["return"]["model"]

    if static_model:
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
    filename = re.sub(" (CPU|Processor)", "", filename)
    filename = re.sub(" @.*", "", filename)
    filename = re.sub(" APU .*", "", filename)
    filename = re.sub(" SE$", "", filename)
    filename = re.sub(" ", "-", filename)
    return "x86_64-cpuid-{}".format(filename)


def output_xml(data, filename):
    leave_pattern = re.compile(
        "^\\s*"
        "(0x[0-9a-f]+)\\s*"
        "(0x[0-9a-f]+):\\s*"
        "eax=(0x[0-9a-f]+)\\s*"
        "ebx=(0x[0-9a-f]+)\\s*"
        "ecx=(0x[0-9a-f]+)\\s*"
        "edx=(0x[0-9a-f]+)\\s*$")

    leave_template = \
        "  <cpuid" \
        " eax_in='{}'" \
        " ecx_in='{}'" \
        " eax='{}'" \
        " ebx='{}'" \
        " ecx='{}'" \
        " edx='{}'" \
        "/>\n"

    msr_template = "  <msr index='0x{:x}' edx='0x{:08x}' eax='0x{:08x}'/>\n"

    print(filename)
    with open(filename, "wt") as f:
        f.write("<!-- {} -->\n".format(data["name"]))
        f.write("<cpudata arch='x86'>\n")
        for line in data["leaves"]:
            match = leave_pattern.match(line)
            f.write(leave_template.format(*match.groups()))
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


def parse(args):
    data = json.load(sys.stdin)

    filename = parse_filename(data)
    filename_xml = "{}.xml".format(filename)
    filename_json = "{}.json".format(filename)

    output_xml(data, filename_xml)
    output_json(data, filename_json)

    if not os.path.isfile(filename_json):
        return
    if os.path.getsize(filename_json) == 0:
        return

    output = subprocess.check_output(
        ["./cpu-cpuid.py", "diff", filename_json],
        universal_newlines=True)
    print(output)


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

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--gather",
        action="store_true",
        help="Acquire data on target system. This is the default.")
    mode.add_argument(
        "--parse",
        action="store_true",
        help="Parse data for libvirt use.")

    args = parser.parse_args()

    if not args.gather and not args.parse:
        args.gather = True

    if not args.path_to_qemu:
        args.path_to_qemu = "qemu-system-x86_64"
        search = [
            "/usr/bin/qemu-system-x86_64",
            "/usr/bin/qemu-kvm",
            "/usr/libexec/qemu-kvm"]
        for f in search:
            if os.path.isfile(f):
                args.path_to_qemu = f

    if args.gather:
        data = gather(args)
        json.dump(data, sys.stdout, indent=2)
    else:
        parse(args)


if __name__ == "__main__":
    main()
