#!/usr/bin/env python3

import argparse
import fcntl
import json
import os
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
        if line:
            yield json.loads(line)


def gather_static_model(args):
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

    for o in output:
        if o.get("id") == "model-expansion":
            return o["return"]["model"]

    return None


def gather_full_model(args, static_model):
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

    args = parser.parse_args()

    if not args.path_to_qemu:
        args.path_to_qemu = "qemu-system-x86_64"
        search = [
            "/usr/bin/qemu-system-x86_64",
            "/usr/bin/qemu-kvm",
            "/usr/libexec/qemu-kvm"]
        for f in search:
            if os.path.isfile(f):
                args.path_to_qemu = f

    name = gather_name(args)
    print("model name\t: {}".format(name))

    leaves = gather_cpuid_leaves(args)
    print("CPU:")
    for leave in leaves:
        print("   {}".format(leave))
    print()

    via, msr = gather_msr()
    if via is not None:
        print("MSR{}:".format(via))
        for key, value in sorted(msr.items()):
            print("   0x{:x}: 0x{:016x}\n".format(int(key), value))

    static_model = gather_static_model(args)
    model = gather_full_model(args, static_model)
    for o in model:
        print(json.dumps(o))

    print(end="", flush=True)
    os.environ["CPU_GATHER_PY"] = "true"
    os.environ["qemu"] = args.path_to_qemu
    os.environ["model"] = json.dumps(static_model) if static_model else ""
    subprocess.check_call("./cpu-gather.sh")


if __name__ == "__main__":
    main()
