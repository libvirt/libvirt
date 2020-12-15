#!/usr/bin/env python3

import argparse
import os
import subprocess


def gather_name(args):
    if args.name:
        return args.name

    with open("/proc/cpuinfo", "rt") as f:
        for line in f.readlines():
            if line.startswith("model name"):
                return line.split(":", 2)[1].strip()

    exit("Error: '/proc/cpuinfo' does not contain a model name.\n"
         "Use '--model' to set a model name.")


def main():
    parser = argparse.ArgumentParser(description="Gather cpu test data")
    parser.add_argument(
        "--name",
        help="CPU model name. "
        "If unset, model name is read from '/proc/cpuinfo'.")

    args = parser.parse_args()

    name = gather_name(args)
    print("model name\t: {}".format(name))

    print(end="", flush=True)
    os.environ["CPU_GATHER_PY"] = "true"
    subprocess.check_call("./cpu-gather.sh")


if __name__ == "__main__":
    main()
