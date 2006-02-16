#!/usr/bin/python -u
import libvirt
import sys

conn = libvirt.openReadOnly(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

xmldesc="""<domain type='xen'>
  <name>test</name>
  <os>
    <type>linux</type>
    <kernel>/boot/vmlinuz-2.6.15-1.43_FC5guest</kernel>
    <initrd>/boot/initrd-2.6.15-1.43_FC5guest.img</initrd>
    <cmdline> root=/dev/sda1 ro selinux=0 3</cmdline>
  </os>
  <memory>131072</memory>
  <vcpu>1</vcpu>
  <devices>
    <disk type='file'>
      <source file='/u/fc4.img'/>
      <target dev='sda1'/>
    </disk>
    <interface type='bridge'>
      <source bridge='xenbr0'/>
      <mac address='aa:00:00:00:00:12'/>
      <script path='/etc/xen/scripts/vif-bridge'/>
    </interface>
  </devices>
</domain>
"""
dom = conn.createLinux(xmldesc, 0)
if dom == None:
    print 'Failed to create a domain'
    sys.exit(1)

# print dom0

print "Domain: id %d running %s" % (dom.ID(), dom.OSType())
print dom.info()
del dom
del conn
print "OK"

sys.exit(0)
