#!/usr/bin/env python3

import os
import subprocess


def main():
    os.environ["CPU_GATHER_PY"] = "true"
    subprocess.check_call("./cpu-gather.sh")


if __name__ == "__main__":
    main()
