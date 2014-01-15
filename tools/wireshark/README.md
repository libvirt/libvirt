About
=====
This is the project of Google Summer of Code 2013 accepted by QEMU.org and
libvirt community.  The goal of this project is, provide Wireshark dissector for
Libvirt RPC protocol. It will provide Libvirt packet overview/detail analysing
in Wireshark. Furthermore, it will be able to build(generated) from RPC protocol
definition placed in Libvirt source tree to support latest protocol
specification.

See also:
- http://www.google-melange.com/gsoc/project/google/gsoc2013/kawamuray/7001
- http://wiki.qemu.org/Features/LibvirtWiresharkDissector

Installation
=============
Run ./configure with --with-wireshark-dissector option enabled.
Then dissector will compiled with libvirt itself.

Add/Remove protocol from dissector's support
--------------------------------------------
Modify variable WS\_DISSECTOR\_PROTO\_FILES in tools/wireshark/src/Makefile.am.

Changing installation directory
-------------------------------
You can change installation directory of pluggable shared object(libvirt.so) by
specifying --with-ws-plugindir=<path>.

You can install libvirt.so into your local wireshark plugin directory:

    ./configure --with-wireshark-dissector \
        --with-ws-plugindir=$HOME/.wireshark/plugins
