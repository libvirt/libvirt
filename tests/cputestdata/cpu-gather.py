#!/usr/bin/env python3

import os
import subprocess


def gather_name():
    with open("/proc/cpuinfo", "rt") as f:
        for line in f.readlines():
            if line.startswith("model name"):
                return line.split(":", 2)[1].strip()

    exit("Error: '/proc/cpuinfo' does not contain a model name.")


def main():
    name = gather_name()
    print("model name\t: {}".format(name))

    print(end="", flush=True)
    os.environ["CPU_GATHER_PY"] = "true"
    subprocess.check_call("./cpu-gather.sh")


if __name__ == "__main__":
    main()
