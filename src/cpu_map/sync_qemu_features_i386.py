#!/usr/bin/env python3

import argparse
import json
import subprocess
import xml.etree.ElementTree


def ignore_feature(feature):
    ignored_features = [
        # VIA/Cyrix/Centaur-defined CPU features
        # CPUID level 0xC0000001, word 5
        "ace2",
        "ace2-en",
        "phe",
        "phe-en",
        "pmm",
        "pmm-en",
        "xcrypt",
        "xcrypt-en",
        "xstore",
        "xstore-en",

        # non-features
        "check",
        "cpuid-0xb",
        "enforce",
        "fill-mtrr-mask",
        "full-cpuid-auto-level",
        "full-width-write",
        "host-cache-info",
        "host-phys-bits",
        "hotpluggable",
        "hotplugged",
        "hv-apicv",
        "hv-avic",
        "hv-crash",
        "hv-emsr-bitmap",
        "hv-enforce-cpuid",
        "hv-evmcs",
        "hv-frequencies",
        "hv-ipi",
        "hv-passthrough",
        "hv-reenlightenment",
        "hv-relaxed",
        "hv-reset",
        "hv-runtime",
        "hv-stimer",
        "hv-stimer-direct",
        "hv-syndbg",
        "hv-synic",
        "hv-time",
        "hv-tlbflush",
        "hv-tlbflush-direct",
        "hv-tlbflush-ext",
        "hv-vapic",
        "hv-vpindex",
        "hv-xmm-input",
        "kvm",
        "kvm-asyncpf",
        "kvm-asyncpf-int",
        "kvm-hint-dedicated",
        "kvm-mmu",
        "kvm-msi-ext-dest-id",
        "kvm-no-smi-migration",
        "kvm-nopiodelay",
        "kvm-poll-control",
        "kvm-pv-enforce-cpuid",
        "kvm-pv-eoi",
        "kvm-pv-ipi",
        "kvm-pv-sched-yield",
        "kvm-pv-tlb-flush",
        "kvm-pv-unhalt",
        "kvm-steal-time",
        "kvm_asyncpf",
        "kvm_asyncpf_int",
        "kvm_mmu",
        "kvm_nopiodelay",
        "kvm_poll_control",
        "kvm_pv_eoi",
        "kvm_pv_unhalt",
        "kvm_steal_time",
        "kvmclock",
        "kvmclock-stable-bit",
        "l3-cache",
        "legacy-cache",
        "lmce",
        "migratable",
        "pmu",
        "realized",
        "start-powered-off",
        "tcg-cpuid",
        "vmware-cpuid-freq",
        "xen-vapic",
    ]

    if feature["type"] != "bool":
        return True

    name = feature["name"]

    if name.startswith("x-") or name.startswith("vmx-"):
        return True

    if name in ignored_features:
        return True

    return False


def get_qemu_feature_list(path_to_qemu):
    cmd = [
        path_to_qemu,
        "-machine", "accel=kvm",
        "-cpu", "host",
        "-nodefaults",
        "-nographic",
        "-qmp",
        "stdio"
    ]

    request = """
    {
        "execute": "qmp_capabilities"
    }
    {
        "execute": "qom-list-properties",
        "arguments": {
            "typename": "max-x86_64-cpu"
        },
        "id": "qom-list-properties"
    }
    {
        "execute": "quit"
    }
    """

    decoder = json.JSONDecoder()
    output = subprocess.check_output(cmd, input=request, text=True)
    while output:
        obj, idx = decoder.raw_decode(output)
        output = output[idx:].strip()
        if obj.get("id") != "qom-list-properties":
            continue
        for feature in obj["return"]:
            if ignore_feature(feature):
                continue
            yield feature["name"]


def get_libvirt_feature_list(path_to_featuresfile):
    dom = xml.etree.ElementTree.parse(path_to_featuresfile)
    for feature in dom.getroot().iter("feature"):
        yield feature.get("name")
        for alias in feature:
            if alias.tag == "alias" and alias.get("source") == "qemu":
                yield alias.get("name")


def main():
    parser = argparse.ArgumentParser(
        description="Synchronize x86 cpu features from QEMU i386 target.")
    parser.add_argument(
        "--qemu",
        help="Path to qemu executable",
        default="qemu-system-x86_64",
        type=str)
    parser.add_argument(
        "--features",
        help="Path to 'src/cpu_map/x86_features.xml' file in "
             "the libvirt repository",
        default="x86_features.xml",
        type=str)

    args = parser.parse_args()

    qfeatures = get_qemu_feature_list(args.qemu)
    lfeatures = list(get_libvirt_feature_list(args.features))
    missing = [f for f in sorted(qfeatures) if f not in lfeatures]

    if missing:
        print("The following features were reported by qemu but are "
              "unknown to libvirt:")
        for feature in missing:
            print(" *", feature)

    return len(missing) != 0


if __name__ == "__main__":
    exit(main())
