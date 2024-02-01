#!/usr/bin/env python3

import argparse
import os
import re


# features in qemu that we do not want in libvirt
FEATURES_IGNORE = (
    "kvm-asyncpf",
    "kvm-asyncpf-int",
    "kvm-hint-dedicated",
    "kvm-mmu",
    "kvm-msi-ext-dest-id",
    "kvm-nopiodelay",
    "kvm-poll-control",
    "kvm-pv-eoi",
    "kvm-pv-ipi",
    "kvm-pv-sched-yield",
    "kvm-pv-tlb-flush",
    "kvm-pv-unhalt",
    "kvm-steal-time",
    "kvmclock",
    "kvmclock-stable-bit",

    "xstore",
    "xstore-en",
    "xcrypt",
    "xcrypt-en",
    "ace2",
    "ace2-en",
    "phe",
    "phe-en",
    "pmm",
    "pmm-en",

    "full-width-write",
)


# features in libvirt, that qemu does not know. as python cannot use dicts
# as keys in other dicts, use tuples. three-tuples "eax, ecx, register name"
# for cpuid features; one-tuples "index" for msrs. The values for the dict are
# mappings from "bit index" to "feature name".
FEATURES_EXTRA = {
    (0x00000001, None, "ecx"): {
        27: "osxsave",
    },
    (0x00000007, 0x0000, "ebx"): {
        12: "cmt",
    },
    (0x00000007, 0x0000, "ecx"): {
        4: "ospke",
    },
    (0x00000007, 0x0000, "edx"): {
        18: "pconfig",
    },
    (0x0000000f, 0x0001, "edx"): {
        1: "mbm_total",
        2: "mbm_local",
    },
    (0x80000001, None, "ecx"): {
        18: "cvt16",
    },
    (0x0000048c,): {
        8: "vmx-ept-uc",
        14: "vmx-ept-wb",
        41: "vmx-invvpid-single-context",               # wrong name in qemu
        43: "vmx-invvpid-single-context-noglobals",     # wrong name in qemu
    }
}


# alias information to add to generated file
FEATURES_ALIASES = {
    "arch-capabilities": (
        ("arch_capabilities", "linux"),
    ),
    "cmp_legacy": (
        ("cmp-legacy", "qemu"),
    ),
    "cmt": (
        ("cqm", "linux"),
    ),
    "ds_cpl": (
        ("ds-cpl", "qemu"),
    ),
    "fxsr_opt": (
        ("ffxsr", "qemu"),
        ("fxsr-opt", "qemu"),
    ),
    "lahf_lm": (
        ("lahf-lm", "qemu"),
    ),
    "lm": (
        ("i64", "qemu"),
    ),
    "md-clear": (
        ("md_clear", "linux"),
    ),
    "nodeid_msr": (
        ("nodeid-msr", "qemu"),
    ),
    "nrip-save": (
        ("nrip_save", "qemu"),
    ),
    "nx": (
        ("xd", "qemu"),
    ),
    "pause-filter": (
        ("pause_filter", "qemu"),
    ),
    "pclmuldq": (
        ("pclmulqdq", "qemu"),
    ),
    "perfctr_core": (
        ("perfctr-core", "qemu"),
    ),
    "perfctr_nb": (
        ("perfctr-nb", "qemu"),
    ),
    "pni": (
        ("sse3", "qemu"),
    ),
    "sse4.1": (
        ("sse4-1", "qemu"),
        ("sse4_1", "qemu"),
    ),
    "sse4.2": (
        ("sse4-2", "qemu"),
        ("sse4_2", "qemu"),
    ),
    "svm-lock": (
        ("svm_lock", "qemu"),
    ),
    "tsc-scale": (
        ("tsc_scale", "qemu"),
    ),
    "tsc_adjust": (
        ("tsc-adjust", "qemu"),
    ),
    "vmcb-clean": (
        ("vmcb_clean", "qemu"),
    ),
    "vmx-invvpid-single-context-noglobals": (
        ("vmx-invept-single-context-noglobals", "qemu"),
    ),
}


# list non-migratable features here
FEATURES_NON_MIGRATABLE = (
    "xsaves",
    "invtsc",
)


# mapping from "symbol name" to "value" for "#define"s in qemu source code
_CONSTANTS = dict()


# tree of known features. top level index is either "cpuid" or "msr".
# further indices for cpuid: eax_in, ecx_in (may be `None`), register name
# further indices for msr: index
_FEATURES = dict()


# fill _CONSTANTS with the #defines from qemu source code
def read_headers(path):
    pattern_define = re.compile("^#define\\s+(\\S+)\\s+(.*)$")

    headers = (
        "include/standard-headers/asm-x86/kvm_para.h",
        "target/i386/cpu.h",
    )

    _CONSTANTS["true"] = "1"

    for header in headers:
        with open(os.path.join(path, header), "tr") as f:
            for line in f.readlines():
                match = pattern_define.match(line)
                if match:
                    key = match.group(1)
                    val = match.group(2)
                    _CONSTANTS[key] = val


# add new cpuid feature bit
def add_feature_cpuid(eax, ecx, reg, bit, name):
    if not name:
        return

    if "cpuid" not in _FEATURES:
        _FEATURES["cpuid"] = dict()

    if eax not in _FEATURES["cpuid"]:
        _FEATURES["cpuid"][eax] = dict()

    if ecx not in _FEATURES["cpuid"][eax]:
        _FEATURES["cpuid"][eax][ecx] = dict()

    if reg not in _FEATURES["cpuid"][eax][ecx]:
        _FEATURES["cpuid"][eax][ecx][reg] = dict()

    _FEATURES["cpuid"][eax][ecx][reg][bit] = name


# add new msr feature bit
def add_feature_msr(msr, bit, name):
    if not name:
        return

    if "msr" not in _FEATURES:
        _FEATURES["msr"] = dict()

    if msr not in _FEATURES["msr"]:
        _FEATURES["msr"][msr] = dict()

    _FEATURES["msr"][msr][bit] = name


# add features from EXTRA_FEATURE to the list of known features
def add_extra_features():
    for key, val in FEATURES_EXTRA.items():
        for bit, name in val.items():
            if len(key) == 3:
                add_feature_cpuid(key[0], key[1], key[2], bit, name)
            else:
                add_feature_msr(key[0], bit, name)


# add a feature from qemu to the list of known features. translates features
# names according to FEATURE_ALIASES and applies symbolic values defined in
# _CONSTANTS.
def add_feature_qemu(query, data):
    # split names into individual items
    data = [n.strip() for n in "".join(data).split(",")]

    names = dict()
    if any([e.startswith("[") for e in data]):
        for entry in data:
            entry = entry.strip()
            if not entry:
                continue
            index, name = entry.split("=", 2)
            index = int(index.strip().strip("[").strip("]"), 0)
            names[index] = name.strip().strip("\"")
    else:
        for index, name in enumerate(data):
            if not name or name == "NULL":
                continue
            name = name.strip("\"")
            if name in FEATURES_IGNORE:
                continue
            names[index] = name.strip("\"")

    # cut out part between "{" and "}". easiest way to get rid of unwanted
    # extra info such as ".tcg_features" or multi line comments
    query = "".join(query).split("{")[1].split("}")[0]

    eax = None
    ecx = None
    reg = None
    msr = None
    for entry in [e.strip() for e in query.split(",")]:
        if not entry:
            continue
        left, right = [e.strip() for e in entry.split("=", 2)]
        if left == ".eax":
            eax = int(_CONSTANTS.get(right, right), 0)
        if left == ".ecx":
            ecx = int(_CONSTANTS.get(right, right), 0)
        if left == ".reg":
            reg = right.lower()[2:]
        if left == ".index":
            msr = int(_CONSTANTS.get(right, right), 0)

    # qemu defines some empty feature words, filter them out
    if not names:
        return
    if all([e is None for e in names.values()]):
        return

    # apply name translation and add to list of known features
    for bit, name in sorted(names.items()):
        for newname, data in FEATURES_ALIASES.items():
            for oldname, source in data:
                if name == oldname and source == "qemu":
                    name = newname

        if msr:
            add_feature_msr(msr, bit, name)
        else:
            add_feature_cpuid(eax, ecx, reg, bit, name)


# read the `feature_word_info` struct from qemu's cpu.c into a list of strings
def read_cpu_c(path):
    pattern_comment = re.compile("/\\*.*?\\*/")
    marker_begin = "FeatureWordInfo feature_word_info[FEATURE_WORDS] = {\n"
    marker_end = "};\n"

    with open(os.path.join(path, "target/i386/cpu.c"), "tr") as f:
        # skip until begin marker
        while True:
            line = f.readline()
            if not line:
                exit("begin marker not found in cpu.c")
            if line == marker_begin:
                break

        # read until end marker
        while True:
            line = f.readline()
            if not line:
                exit("end marker not found in cpu.c")
            if line == marker_end:
                break

            # remove comments and white space
            line = re.sub(pattern_comment, "", line).strip()

            yield line


# simple state machine to extract feature names and definitions from extracted
# qemu source code
def parse_feature_words(lines):
    state_waiting_for_type = 1
    state_waiting_for_names = 2
    state_read_names = 3
    state_waiting_for_query = 4
    state_read_query = 5

    pattern_type = re.compile("^\\.type\\s*=\\s*(.+)$")
    pattern_names = re.compile("^\\.feat_names\\s*=\\s*{$")
    pattern_data = re.compile("^\\.(cpuid|msr).*$")
    pattern_end = re.compile("^},?$")

    state = state_waiting_for_type
    for line in lines:
        if state == state_waiting_for_type:
            match = pattern_type.match(line)
            if match:
                data_names = list()
                data_query = list()
                state = state_waiting_for_names

        elif state == state_waiting_for_names:
            # special case for missing ".feat_names" entry:
            match = pattern_data.match(line)
            if match:
                data_query.append(line)
                state = state_read_query
                continue

            match = pattern_names.match(line)
            if match:
                state = state_read_names

        elif state == state_read_names:
            match = pattern_end.match(line)
            if match:
                state = state_waiting_for_query
            else:
                data_names.append(line)

        elif state == state_waiting_for_query:
            match = pattern_data.match(line)
            if match:
                data_query.append(line)
                state = state_read_query

        elif state == state_read_query:
            match = pattern_end.match(line)
            data_query.append(line)
            if match:
                state = state_waiting_for_type
                add_feature_qemu(data_query, data_names)

        else:
            exit("parsing state machine in invalid state")

    if state != state_waiting_for_type:
        exit("parsing incomplete")


# generate x86_features.xml from list of known features
def write_output(path):
    with open(path, "tw") as f:
        f.write("<!--\n  Generated file, do not edit!\n  Use the ")
        f.write("sync_qemu_features_i386.py script to make changes.\n-->\n\n")
        f.write("<cpus>\n")

        for eax in sorted(_FEATURES["cpuid"]):
            for ecx in sorted(_FEATURES["cpuid"][eax]):
                for reg in sorted(_FEATURES["cpuid"][eax][ecx]):
                    f.write(f"\n  <!-- cpuid level 0x{eax:08x}")
                    if ecx is not None:
                        f.write(f", 0x{ecx:04x}")
                    f.write(f" ({reg:s}) -->\n")

                    names = sorted(_FEATURES["cpuid"][eax][ecx][reg].items())
                    for bit, name in names:
                        mask = 1 << bit
                        f.write(f"  <feature name='{name}'")
                        if name in FEATURES_NON_MIGRATABLE:
                            f.write(" migratable='no'")
                        f.write(">\n")
                        for alias in FEATURES_ALIASES.get(name, []):
                            f.write(f"    <alias name='{alias[0]}'")
                            f.write(f" source='{alias[1]}'/>\n")
                        f.write(f"    <cpuid eax_in='0x{eax:08x}' ")
                        if ecx is not None:
                            f.write(f"ecx_in='0x{ecx:08x}' ")
                        f.write(f"{reg:s}='0x{mask:08x}'/>\n")
                        f.write("  </feature>\n")

        for msr in sorted(_FEATURES["msr"]):
            f.write(f"\n  <!-- msr 0x{msr:08x} -->\n")
            names = sorted(_FEATURES["msr"][msr].items())
            for bit, name in names:
                mask = 1 << bit
                f.write(f"  <feature name='{name}'")
                if name in FEATURES_NON_MIGRATABLE:
                    f.write(" migratable='no'")
                f.write(">\n")
                for alias in FEATURES_ALIASES.get(name, []):
                    f.write(f"    <alias name='{alias[0]}'")
                    f.write(f" source='{alias[1]}'/>\n")
                f.write(f"    <msr index='0x{msr:08x}' ")
                f.write(f"edx='0x{(mask >> 32):08x}' ")
                f.write(f"eax='0x{(mask & 0xffffffff):08x}'/>\n")
                f.write("  </feature>\n")

        f.write("</cpus>\n")


def main():
    dirname = os.path.dirname(__file__)

    parser = argparse.ArgumentParser(
        description="Synchronize x86 cpu features from QEMU."
    )
    parser.add_argument(
        "qemu",
        help="Path to qemu source code",
        default=os.path.realpath(os.path.join(dirname, "../../../qemu")),
        nargs="?",
        type=os.path.realpath,
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to output file",
        default=os.path.realpath(os.path.join(dirname, "x86_features.xml")),
        type=os.path.realpath
    )
    args = parser.parse_args()

    if not os.path.isdir(args.qemu):
        parser.print_help()
        exit("qemu source directory not found")

    read_headers(args.qemu)
    lines = read_cpu_c(args.qemu)
    parse_feature_words(lines)
    add_extra_features()
    write_output(args.output)

    print(
        "After adding new features, update existing test files by running "
        "`tests/cputestdata/cpu-data.py diff tests/cputestdata/"
        "x86_64-cpuid-*.json`"
    )


if __name__ == "__main__":
    exit(main())
