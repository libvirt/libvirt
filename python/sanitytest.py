#!/usr/bin/python

import libvirt

globals = dir(libvirt)

# Sanity test that the generator hasn't gone wrong

# Look for core classes
assert("virConnect" in globals)
assert("virDomain" in globals)
assert("virDomainSnapshot" in globals)
assert("virInterface" in globals)
assert("virNWFilter" in globals)
assert("virNodeDevice" in globals)
assert("virNetwork" in globals)
assert("virSecret" in globals)
assert("virStoragePool" in globals)
assert("virStorageVol" in globals)
assert("virStream" in globals)
assert("VIR_CONNECT_RO" in globals)

# Error related bits
assert("libvirtError" in globals)
assert("VIR_ERR_AUTH_FAILED" in globals)
assert("virGetLastError" in globals)

# Some misc methods
assert("virInitialize" in globals)
assert("virEventAddHandle" in globals)
assert("virEventRegisterDefaultImpl" in globals)
