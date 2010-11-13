#!/usr/bin/env python
# esxlist - list active domains of an ESX host and print some info.
#           also demonstrates how to use the libvirt.openAuth() method

import libvirt
import sys
import os
import libxml2
import getpass


def usage():
    print "Usage: %s HOSTNAME" % sys.argv[0]
    print "       List active domains of HOSTNAME and print some info"


# This is the callback method passed to libvirt.openAuth() (see below).
#
# The credentials argument is a list of credentials that libvirt (actually
# the ESX driver) would like to request. An element of this list is itself a
# list containing 5 items (4 inputs, 1 output):
#   - the credential type, e.g. libvirt.VIR_CRED_AUTHNAME
#   - a prompt to be displayed to the user
#   - a challenge, the ESX driver sets this to the hostname to allow automatic
#     distinction between requests for ESX and vCenter credentials
#   - a default result for the request
#   - a place to store the actual result for the request
#
# The user_data argument is the user data item of the auth argument (see below)
# passed to libvirt.openAuth().
def request_credentials(credentials, user_data):
    for credential in credentials:
        if credential[0] == libvirt.VIR_CRED_AUTHNAME:
            # prompt the user to input a authname. display the provided message
            credential[4] = raw_input(credential[1] + ": ")

            # if the user just hits enter raw_input() returns an empty string.
            # in this case return the default result through the last item of
            # the list
            if len(credential[4]) == 0:
                credential[4] = credential[3]
        elif credential[0] == libvirt.VIR_CRED_NOECHOPROMPT:
            # use the getpass module to prompt the user to input a password.
            # display the provided message and return the result through the
            # last item of the list
            credential[4] = getpass.getpass(credential[1] + ": ")
        else:
            return -1

    return 0


def print_section(title):
    print "\n%s" % title
    print "=" * 60


def print_entry(key, value):
    print "%-10s %-10s" % (key, value)


def print_xml(key, ctx, path):
    res = ctx.xpathEval(path)

    if res is None or len(res) == 0:
        value = "Unknown"
    else:
        value = res[0].content

    print_entry(key, value)

    return value


if len(sys.argv) != 2:
    usage()
    sys.exit(2)


hostname = sys.argv[1]

# Connect to libvirt
uri = "esx://%s/?no_verify=1" % hostname

# The auth argument is a list that contains 3 items:
#   - a list of supported credential types
#   - a callable that takes 2 arguments
#   - user data that will be passed to the callable as second argument
#
# In this example the supported credential types are VIR_CRED_AUTHNAME and
# VIR_CRED_NOECHOPROMPT, the callable is the unbound method request_credentials
# (see above) and the user data is None.
#
# libvirt (actually the ESX driver) will call the callable to request
# credentials in order to log into the ESX host. The callable would also be
# called if the connection URI would reference a vCenter to request credentials
# in order to log into the vCenter
auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_NOECHOPROMPT],
        request_credentials, None]
conn = libvirt.openAuth(uri, auth, 0)

if conn is None:
    print "Failed to open connection to %s" % hostname
    sys.exit(1)

state_names = { libvirt.VIR_DOMAIN_RUNNING  : "running",
                libvirt.VIR_DOMAIN_BLOCKED  : "idle",
                libvirt.VIR_DOMAIN_PAUSED   : "paused",
                libvirt.VIR_DOMAIN_SHUTDOWN : "in shutdown",
                libvirt.VIR_DOMAIN_SHUTOFF  : "shut off",
                libvirt.VIR_DOMAIN_CRASHED  : "crashed",
                libvirt.VIR_DOMAIN_NOSTATE  : "no state" }

for id in conn.listDomainsID():
    domain = conn.lookupByID(id)
    info = domain.info()

    print_section("Domain " + domain.name())
    print_entry("ID:", id)
    print_entry("UUID:", domain.UUIDString())
    print_entry("State:", state_names[info[0]])
    print_entry("MaxMem:", info[1])
    print_entry("UsedMem:", info[2])
    print_entry("VCPUs:", info[3])

    # Read some info from the XML desc
    print_section("Devices of " + domain.name())

    xmldesc = domain.XMLDesc(0)
    doc = libxml2.parseDoc(xmldesc)
    ctx = doc.xpathNewContext()
    devs = ctx.xpathEval("/domain/devices/*")
    first = True

    for d in devs:
        ctx.setContextNode(d)

        if not first:
            print "------------------------------------------------------------"
        else:
            first = False

        print_entry("Device", d.name)

        type = print_xml("Type:", ctx, "@type")

        if type == "file":
            print_xml("Source:", ctx, "source/@file")
            print_xml("Target:", ctx, "target/@dev")
        elif type == "block":
            print_xml("Source:", ctx, "source/@dev")
            print_xml("Target:", ctx, "target/@dev")
        elif type == "bridge":
            print_xml("Source:", ctx, "source/@bridge")
            print_xml("MAC Addr:", ctx, "mac/@address")
