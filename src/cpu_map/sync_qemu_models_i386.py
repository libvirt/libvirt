#!/usr/bin/env python3

import argparse
import copy
import os
import re
import xml.etree.ElementTree

import lark


def translate_vendor(name):
    T = {
        "CPUID_VENDOR_AMD": "AMD",
        "CPUID_VENDOR_INTEL": "Intel",
        "CPUID_VENDOR_HYGON": "Hygon",
    }

    if name in T:
        return T[name]

    print("warning: Unknown vendor '{}'".format(name))
    return name


def translate_feature(name):
    T = {
        "CPUID_6_EAX_ARAT": "arat",
        "CPUID_7_0_EBX_ADX": "adx",
        "CPUID_7_0_EBX_AVX2": "avx2",
        "CPUID_7_0_EBX_AVX512BW": "avx512bw",
        "CPUID_7_0_EBX_AVX512CD": "avx512cd",
        "CPUID_7_0_EBX_AVX512DQ": "avx512dq",
        "CPUID_7_0_EBX_AVX512ER": "avx512er",
        "CPUID_7_0_EBX_AVX512F": "avx512f",
        "CPUID_7_0_EBX_AVX512IFMA": "avx512ifma",
        "CPUID_7_0_EBX_AVX512PF": "avx512pf",
        "CPUID_7_0_EBX_AVX512VL": "avx512vl",
        "CPUID_7_0_EBX_BMI1": "bmi1",
        "CPUID_7_0_EBX_BMI2": "bmi2",
        "CPUID_7_0_EBX_CLFLUSHOPT": "clflushopt",
        "CPUID_7_0_EBX_CLWB": "clwb",
        "CPUID_7_0_EBX_ERMS": "erms",
        "CPUID_7_0_EBX_FSGSBASE": "fsgsbase",
        "CPUID_7_0_EBX_HLE": "hle",
        "CPUID_7_0_EBX_INVPCID": "invpcid",
        "CPUID_7_0_EBX_MPX": "mpx",
        "CPUID_7_0_EBX_RDSEED": "rdseed",
        "CPUID_7_0_EBX_RTM": "rtm",
        "CPUID_7_0_EBX_SHA_NI": "sha-ni",
        "CPUID_7_0_EBX_SMAP": "smap",
        "CPUID_7_0_EBX_SMEP": "smep",
        "CPUID_7_0_ECX_AVX512BITALG": "avx512bitalg",
        "CPUID_7_0_ECX_AVX512VNNI": "avx512vnni",
        "CPUID_7_0_ECX_AVX512_VBMI": "avx512vbmi",
        "CPUID_7_0_ECX_AVX512_VBMI2": "avx512vbmi2",
        "CPUID_7_0_ECX_AVX512_VPOPCNTDQ": "avx512-vpopcntdq",
        "CPUID_7_0_ECX_BUS_LOCK_DETECT": "bus-lock-detect",
        "CPUID_7_0_ECX_CLDEMOTE": "cldemote",
        "CPUID_7_0_ECX_GFNI": "gfni",
        "CPUID_7_0_ECX_LA57": "la57",
        "CPUID_7_0_ECX_MOVDIR64B": "movdir64b",
        "CPUID_7_0_ECX_MOVDIRI": "movdiri",
        "CPUID_7_0_ECX_PKU": "pku",
        "CPUID_7_0_ECX_RDPID": "rdpid",
        "CPUID_7_0_ECX_UMIP": "umip",
        "CPUID_7_0_ECX_VAES": "vaes",
        "CPUID_7_0_ECX_VPCLMULQDQ": "vpclmulqdq",
        "CPUID_7_0_EDX_AMX_BF16": "amx-bf16",
        "CPUID_7_0_EDX_AMX_INT8": "amx-int8",
        "CPUID_7_0_EDX_AMX_TILE": "amx-tile",
        "CPUID_7_0_EDX_ARCH_CAPABILITIES": "arch-capabilities",
        "CPUID_7_0_EDX_AVX512_4FMAPS": "avx512-4fmaps",
        "CPUID_7_0_EDX_AVX512_4VNNIW": "avx512-4vnniw",
        "CPUID_7_0_EDX_AVX512_FP16": "avx512-fp16",
        "CPUID_7_0_EDX_CORE_CAPABILITY": "core-capability",
        "CPUID_7_0_EDX_FSRM": "fsrm",
        "CPUID_7_0_EDX_SERIALIZE": "serialize",
        "CPUID_7_0_EDX_SPEC_CTRL": "spec-ctrl",
        "CPUID_7_0_EDX_SPEC_CTRL_SSBD": "ssbd",
        "CPUID_7_0_EDX_STIBP": "stibp",
        "CPUID_7_0_EDX_TSX_LDTRK": "tsx-ldtrk",
        "CPUID_7_1_EAX_AMX_FP16": "amx-fp16",
        "CPUID_7_1_EAX_AVX512_BF16": "avx512-bf16",
        "CPUID_7_1_EAX_AVX_VNNI": "avx-vnni",
        "CPUID_7_1_EAX_FSRC": "fsrc",
        "CPUID_7_1_EAX_FSRS": "fsrs",
        "CPUID_7_1_EAX_FZRM": "fzrm",
        "CPUID_7_1_EDX_PREFETCHITI": "prefetchiti",
        "CPUID_7_2_EDX_MCDT_NO": "mcdt-no",
        "CPUID_8000_0008_EBX_AMD_PSFD": "amd-psfd",
        "CPUID_8000_0008_EBX_AMD_SSBD": "amd-ssbd",
        "CPUID_8000_0008_EBX_CLZERO": "clzero",
        "CPUID_8000_0008_EBX_IBPB": "ibpb",
        "CPUID_8000_0008_EBX_IBRS": "ibrs",
        "CPUID_8000_0008_EBX_STIBP": "amd-stibp",
        "CPUID_8000_0008_EBX_STIBP_ALWAYS_ON": "stibp-always-on",
        "CPUID_8000_0008_EBX_WBNOINVD": "wbnoinvd",
        "CPUID_8000_0008_EBX_XSAVEERPTR": "xsaveerptr",
        "CPUID_8000_0021_EAX_AUTO_IBRS": "auto-ibrs",
        "CPUID_8000_0021_EAX_LFENCE_ALWAYS_SERIALIZING":
            "lfence-always-serializing",
        "CPUID_8000_0021_EAX_NULL_SEL_CLR_BASE": "null-sel-clr-base",
        "CPUID_8000_0021_EAX_No_NESTED_DATA_BP": "no-nested-data-bp",
        "CPUID_ACPI": "acpi",
        "CPUID_APIC": "apic",
        "CPUID_CLFLUSH": "clflush",
        "CPUID_CMOV": "cmov",
        "CPUID_CX8": "cx8",
        "CPUID_DE": "de",
        "CPUID_D_1_EAX_XFD": "xfd",
        "CPUID_EXT2_3DNOW": "3dnow",
        "CPUID_EXT2_3DNOWEXT": "3dnowext",
        "CPUID_EXT2_FFXSR": "fxsr_opt",
        "CPUID_EXT2_LM": "lm",
        "CPUID_EXT2_MMXEXT": "mmxext",
        "CPUID_EXT2_NX": "nx",
        "CPUID_EXT2_PDPE1GB": "pdpe1gb",
        "CPUID_EXT2_RDTSCP": "rdtscp",
        "CPUID_EXT2_SYSCALL": "syscall",
        "CPUID_EXT3_3DNOWPREFETCH": "3dnowprefetch",
        "CPUID_EXT3_ABM": "abm",
        "CPUID_EXT3_CR8LEG": "cr8legacy",
        "CPUID_EXT3_FMA4": "fma4",
        "CPUID_EXT3_LAHF_LM": "lahf_lm",
        "CPUID_EXT3_MISALIGNSSE": "misalignsse",
        "CPUID_EXT3_OSVW": "osvw",
        "CPUID_EXT3_PERFCORE": "perfctr_core",
        "CPUID_EXT3_SSE4A": "sse4a",
        "CPUID_EXT3_SVM": "svm",
        "CPUID_EXT3_TBM": "tbm",
        "CPUID_EXT3_XOP": "xop",
        "CPUID_EXT_AES": "aes",
        "CPUID_EXT_AVX": "avx",
        "CPUID_EXT_CX16": "cx16",
        "CPUID_EXT_F16C": "f16c",
        "CPUID_EXT_FMA": "fma",
        "CPUID_EXT_MOVBE": "movbe",
        "CPUID_EXT_PCID": "pcid",
        "CPUID_EXT_PCLMULQDQ": "pclmuldq",
        "CPUID_EXT_POPCNT": "popcnt",
        "CPUID_EXT_RDRAND": "rdrand",
        "CPUID_EXT_SSE3": "pni",
        "CPUID_EXT_SSE41": "sse4.1",
        "CPUID_EXT_SSE42": "sse4.2",
        "CPUID_EXT_SSSE3": "ssse3",
        "CPUID_EXT_TSC_DEADLINE_TIMER": "tsc-deadline",
        "CPUID_EXT_X2APIC": "x2apic",
        "CPUID_EXT_XSAVE": "xsave",
        "CPUID_FP87": "fpu",
        "CPUID_FXSR": "fxsr",
        "CPUID_MCA": "mca",
        "CPUID_MCE": "mce",
        "CPUID_MMX": "mmx",
        "CPUID_MSR": "msr",
        "CPUID_MTRR": "mtrr",
        "CPUID_PAE": "pae",
        "CPUID_PAT": "pat",
        "CPUID_PGE": "pge",
        "CPUID_PSE": "pse",
        "CPUID_PSE36": "pse36",
        "CPUID_SEP": "sep",
        "CPUID_SS": "ss",
        "CPUID_SSE": "sse",
        "CPUID_SSE2": "sse2",
        "CPUID_SVM_NPT": "npt",
        "CPUID_SVM_NRIPSAVE": "nrip-save",
        "CPUID_SVM_SVME_ADDR_CHK": "svme-addr-chk",
        "CPUID_SVM_VNMI": "vnmi",
        "CPUID_TSC": "tsc",
        "CPUID_VME": "vme",
        "CPUID_XSAVE_XGETBV1": "xgetbv1",
        "CPUID_XSAVE_XSAVEC": "xsavec",
        "CPUID_XSAVE_XSAVEOPT": "xsaveopt",
        "CPUID_XSAVE_XSAVES": "xsaves",
        "MSR_ARCH_CAP_FBSDP_NO": "fbsdp-no",
        "MSR_ARCH_CAP_IBRS_ALL": "ibrs-all",
        "MSR_ARCH_CAP_MDS_NO": "mds-no",
        "MSR_ARCH_CAP_PBRSB_NO": "pbrsb-no",
        "MSR_ARCH_CAP_PSCHANGE_MC_NO": "pschange-mc-no",
        "MSR_ARCH_CAP_PSDP_NO": "psdp-no",
        "MSR_ARCH_CAP_RDCL_NO": "rdctl-no",
        "MSR_ARCH_CAP_SBDR_SSDP_NO": "sbdr-ssdp-no",
        "MSR_ARCH_CAP_SKIP_L1DFL_VMENTRY": "skip-l1dfl-vmentry",
        "MSR_ARCH_CAP_TAA_NO": "taa-no",
        "MSR_CORE_CAP_SPLIT_LOCK_DETECT": "split-lock-detect",
    }

    ignore = any([
        name.startswith("VMX_"),
        name.startswith("vmx-"),
        name.startswith("MSR_VMX_"),
        name in ("0", "model", "model-id", "stepping"),
        name in ("CPUID_EXT_MONITOR", "monitor"),
        name in ("MSR_VMX_BASIC_DUAL_MONITOR", "dual-monitor"),
        name in ("CPUID_EXT3_TOPOEXT", "topoext"),
    ])

    if ignore:
        return None

    if name in T:
        return T[name]

    for v in T.values():
        if name.replace("-", "_") == v.replace("-", "_"):
            return v

    print("warning: Unknown feature '{}'".format(name))
    return name


def readline_cont(f):
    """Read one logical line from a file `f` i.e. continues lines that end in
    a backslash."""

    line = f.readline()
    while line.endswith("\\\n"):
        line = line[:-2] + " " + f.readline()
    return line


def read_builtin_x86_defs(filename):
    """Extract content between begin_mark and end_mark from file `filename` as
    string, while expanding shorthand macros like "I486_FEATURES"."""

    begin_mark = re.compile(
        "^static( const)? X86CPUDefinition builtin_x86_defs\\[\\] = {$")
    end_mark = "};\n"
    shorthand = re.compile("^#define ([A-Z0-9_]+_FEATURES) (.*)$")
    lines = list()
    shorthands = dict()

    with open(filename, "rt") as f:
        while True:
            line = readline_cont(f)
            if not line:
                raise RuntimeError("begin mark not found")
            match = begin_mark.match(line)
            if match:
                break
            match = shorthand.match(line)
            if match:
                # TCG definitions are irrelevant for cpu models
                newk = match.group(1)
                if newk.startswith("TCG_"):
                    continue

                # remove comments, whitespace and bit operators, effectively
                # turning the bitfield into a list
                newv = re.sub("([()|\t\n])|(/\\*.*?\\*/)", " ", match.group(2))

                # resolve recursive shorthands
                for k, v in shorthands.items():
                    newv = newv.replace(k, v)

                shorthands[newk] = newv

        while True:
            line = readline_cont(f)
            if line == end_mark:
                break
            if not line:
                raise RuntimeError("end marker not found")

            # apply shorthands
            for k, v in shorthands.items():
                line = line.replace(k, v)
            lines.append(line)

    return "".join(lines)


def transform(item):
    """Recursively transform a Lark syntax tree into python native objects."""

    if isinstance(item, lark.lexer.Token):
        return str(item)

    if item.data == "list":
        retval = list()
        for child in item.children:
            value = transform(child)
            if value is None:
                continue
            retval.append(value)
        return retval

    if item.data == "map":
        retval = dict()
        for child in item.children:
            if len(child.children) != 2:
                raise RuntimeError("map entry with more than 2 elements")
            key = transform(child.children[0])
            value = transform(child.children[1])
            if key is None:
                raise RuntimeError("map entry with 'None' key")
            if value is None:
                continue
            retval[key] = value
        return retval

    if item.data == "text":
        retval = list()
        for child in item.children:
            value = transform(child)
            if value is None:
                continue
            retval.append(value)
        return " ".join(retval)

    if item.data == "value":
        if item.children:
            raise RuntimeError("empty list is not empty")
        return None

    raise RuntimeError("unexpected item type")


def expand_model(model):
    """Expand a qemu cpu model description that has its feature split up into
    different fields and may have differing versions into several libvirt-
    friendly cpu models."""

    result = {
        "name": model.pop(".name"),
        "vendor": translate_vendor(model.pop(".vendor")),
        "features": set(),
        "extra": dict()}

    if ".family" in model and ".model" in model:
        result["family"] = model.pop(".family")
        result["model"] = model.pop(".model")

    for k in [k for k in model if k.startswith(".features")]:
        v = model.pop(k)
        for feature in v.split():
            translated = translate_feature(feature)
            if translated:
                result["features"].add(translated)

    versions = model.pop(".versions", [])
    for k, v in model.items():
        result["extra"]["model" + k] = v
    yield result

    for version in versions:
        result = copy.deepcopy(result)
        result["name"] = version.pop(".alias", result["name"])

        props = version.pop(".props", dict())
        for k, v in props:
            if k not in ("model-id", "stepping", "model"):
                k = translate_feature(k)
            if k is None:
                continue

            if v == "on":
                result["features"].add(k)
            elif v == "off" and k in result["features"]:
                result["features"].remove(k)
            else:
                result["extra"]["property." + k] = v

        for k, v in version.items():
            result["extra"]["version" + k] = v

        yield result


def output_model(f, model):
    if model["extra"]:
        f.write("<!-- extra info from qemu:\n")
        for k, v in model["extra"].items():
            f.write("  '{}': '{}'\n".format(k, v))
        f.write("-->\n")

    f.write("<cpus>\n")
    f.write("  <model name='{}'>\n".format(model["name"]))
    f.write("    <decode host='on' guest='on'/>\n")
    f.write("    <signature family='{}' model='{}'/>\n".format(
        model["family"], model["model"]))
    f.write("    <vendor name='{}'/>\n".format(model["vendor"]))
    for feature in sorted(model["features"]):
        f.write("    <feature name='{}'/>\n".format(feature))
    f.write("  </model>\n")
    f.write("</cpus>\n")


def main():
    parser = argparse.ArgumentParser(
        description="Synchronize x86 cpu models from QEMU i386 target.")
    parser.add_argument(
        "cpufile",
        help="Path to 'target/i386/cpu.c' file in the QEMU repository",
        type=os.path.realpath)
    parser.add_argument(
        "outdir",
        help="Path to 'src/cpu_map' directory in the libvirt repository",
        type=os.path.realpath)

    args = parser.parse_args()

    builtin_x86_defs = read_builtin_x86_defs(args.cpufile)

    ast = lark.Lark(r"""
        list: value ( "," value )* ","?
        map: keyvalue ( "," keyvalue )* ","?
        keyvalue: IDENTIFIER "=" value
        ?value: text | "{" "}" | "{" list "}" | "{" map "}"
        text: (IDENTIFIER | "\"" (/[^"]+/)? "\"")+
        IDENTIFIER: /[\[\]\._&a-zA-Z0-9]/+
        %ignore (" " | "\r" | "\n" | "\t" | "|" )+
        %ignore "(" ( "X86CPUVersionDefinition" | "PropValue" ) "[])"
        %ignore "//" /.*?/ "\n"
        %ignore "/*" /(.|\n)*?/ "*/"
        """, start="list").parse(builtin_x86_defs)

    models_json = transform(ast)

    models = list()
    for model in models_json:
        models.extend(expand_model(model))

    for model in models:
        name = os.path.join(args.outdir, "x86_{}.xml".format(model["name"]))
        with open(name, "wt") as f:
            output_model(f, model)

    features = set()
    for model in models:
        features.update(model["features"])

    try:
        filename = os.path.join(args.outdir, "x86_features.xml")
        dom = xml.etree.ElementTree.parse(filename)
        known = [x.attrib["name"] for x in dom.getroot().iter("feature")]
        unknown = [x for x in features if x not in known and x is not None]
    except Exception as e:
        unknown = []
        print("warning: Unable to read libvirt x86_features.xml: {}".format(e))

    for x in unknown:
        print("warning: Feature unknown to libvirt: {}".format(x))


if __name__ == "__main__":
    main()
