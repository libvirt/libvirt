#!/usr/bin/env python3

import argparse
import fcntl
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

    args = parser.parse_args()

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

    print(end="", flush=True)
    os.environ["CPU_GATHER_PY"] = "true"
    subprocess.check_call("./cpu-gather.sh")


if __name__ == "__main__":
    main()
