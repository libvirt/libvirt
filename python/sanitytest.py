#!/usr/bin/python

import libvirt

globals = dir(libvirt)

# Sanity test that the generator hasn't gone wrong

# Look for core classes
for clsname in ["virConnect",
                "virDomain",
                "virDomainSnapshot",
                "virInterface",
                "virNWFilter",
                "virNodeDevice",
                "virNetwork",
                "virSecret",
                "virStoragePool",
                "virStorageVol",
                "virStream",
                ]:
    assert(clsname in globals)
    assert(object in getattr(libvirt, clsname).__bases__)

# Constants
assert("VIR_CONNECT_RO" in globals)

# Error related bits
assert("libvirtError" in globals)
assert("VIR_ERR_AUTH_FAILED" in globals)
assert("virGetLastError" in globals)

# Some misc methods
assert("virInitialize" in globals)
assert("virEventAddHandle" in globals)
assert("virEventRegisterDefaultImpl" in globals)
