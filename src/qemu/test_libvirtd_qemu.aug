module Test_libvirtd_qemu =

   let conf = "# Master configuration file for the QEMU driver.
# All settings described here are optional - if omitted, sensible
# defaults are used.

# VNC is configured to listen on 127.0.0.1 by default.
# To make it listen on all public interfaces, uncomment
# this next option.
#
# NB, strong recommendation to enable TLS + x509 certificate
# verification when allowing public access
#
vnc_listen = \"0.0.0.0\"


# Enable use of TLS encryption on the VNC server. This requires
# a VNC client which supports the VeNCrypt protocol extension.
# Examples include vinagre, virt-viewer, virt-manager and vencrypt
# itself. UltraVNC, RealVNC, TightVNC do not support this
#
# It is necessary to setup CA and issue a server certificate
# before enabling this.
#
vnc_tls = 1


# Use of TLS requires that x509 certificates be issued. The
# default it to keep them in /etc/pki/libvirt-vnc. This directory
# must contain
#
#  ca-cert.pem - the CA master certificate
#  server-cert.pem - the server certificate signed with ca-cert.pem
#  server-key.pem  - the server private key
#
# This option allows the certificate directory to be changed
#
vnc_tls_x509_cert_dir = \"/etc/pki/libvirt-vnc\"


# The default TLS configuration only uses certificates for the server
# allowing the client to verify the server's identity and establish
# and encrypted channel.
#
# It is possible to use x509 certificates for authentication too, by
# issuing a x509 certificate to every client who needs to connect.
#
# Enabling this option will reject any client who does not have a
# certificate signed by the CA in /etc/pki/libvirt-vnc/ca-cert.pem
#
vnc_tls_x509_verify = 1


# The default VNC password. Only 8 letters are significant for
# VNC passwords. This parameter is only used if the per-domain
# XML config does not already provide a password. To allow
# access without passwords, leave this commented out. An empty
# string will still enable passwords, but be rejected by QEMU
# effectively preventing any use of VNC. Obviously change this
# example here before you set this
#
vnc_password = \"XYZ12345\"


# Enable use of SASL encryption on the VNC server. This requires
# a VNC client which supports the SASL protocol extension.
# Examples include vinagre, virt-viewer and virt-manager
# itself. UltraVNC, RealVNC, TightVNC do not support this
#
# It is necessary to configure /etc/sasl2/qemu.conf to choose
# the desired SASL plugin (eg, GSSPI for Kerberos)
#
vnc_sasl = 1


# The default SASL configuration file is located in /etc/sasl2/
# When running libvirtd unprivileged, it may be desirable to
# override the configs in this location. Set this parameter to
# point to the directory, and create a qemu.conf in that location
#
vnc_sasl_dir = \"/some/directory/sasl2\"

security_driver = \"selinux\"

user = \"root\"

group = \"root\"

dynamic_ownership = 1

cgroup_controllers = [ \"cpu\", \"devices\" ]

cgroup_device_acl = [ \"/dev/null\", \"/dev/full\", \"/dev/zero\" ]

save_image_format = \"gzip\"

dump_image_format = \"gzip\"

auto_dump_path = \"/var/lib/libvirt/qemu/dump\"

hugetlbfs_mount = \"/dev/hugepages\"

set_process_name = 1

relaxed_acs_check = 1

vnc_allow_host_audio = 1

clear_emulator_capabilities = 0

allow_disk_format_probing = 1

vnc_auto_unix_socket = 1

max_processes = 12345

max_files = 67890

lock_manager = \"fcntl\"

keepalive_interval = 1
keepalive_count = 42
"

   test Libvirtd_qemu.lns get conf =
{ "#comment" = "Master configuration file for the QEMU driver." }
{ "#comment" = "All settings described here are optional - if omitted, sensible" }
{ "#comment" = "defaults are used." }
{ "#empty" }
{ "#comment" = "VNC is configured to listen on 127.0.0.1 by default." }
{ "#comment" = "To make it listen on all public interfaces, uncomment" }
{ "#comment" = "this next option." }
{ "#comment" = "" }
{ "#comment" = "NB, strong recommendation to enable TLS + x509 certificate" }
{ "#comment" = "verification when allowing public access" }
{ "#comment" = "" }
{ "vnc_listen" = "0.0.0.0" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "Enable use of TLS encryption on the VNC server. This requires" }
{ "#comment" = "a VNC client which supports the VeNCrypt protocol extension." }
{ "#comment" = "Examples include vinagre, virt-viewer, virt-manager and vencrypt" }
{ "#comment" = "itself. UltraVNC, RealVNC, TightVNC do not support this" }
{ "#comment" = "" }
{ "#comment" = "It is necessary to setup CA and issue a server certificate" }
{ "#comment" = "before enabling this." }
{ "#comment" = "" }
{ "vnc_tls" = "1" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "Use of TLS requires that x509 certificates be issued. The" }
{ "#comment" = "default it to keep them in /etc/pki/libvirt-vnc. This directory" }
{ "#comment" = "must contain" }
{ "#comment" = "" }
{ "#comment" = "ca-cert.pem - the CA master certificate" }
{ "#comment" = "server-cert.pem - the server certificate signed with ca-cert.pem" }
{ "#comment" = "server-key.pem  - the server private key" }
{ "#comment" = "" }
{ "#comment" = "This option allows the certificate directory to be changed" }
{ "#comment" = "" }
{ "vnc_tls_x509_cert_dir" = "/etc/pki/libvirt-vnc" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "The default TLS configuration only uses certificates for the server" }
{ "#comment" = "allowing the client to verify the server's identity and establish" }
{ "#comment" = "and encrypted channel." }
{ "#comment" = "" }
{ "#comment" = "It is possible to use x509 certificates for authentication too, by" }
{ "#comment" = "issuing a x509 certificate to every client who needs to connect." }
{ "#comment" = "" }
{ "#comment" = "Enabling this option will reject any client who does not have a" }
{ "#comment" = "certificate signed by the CA in /etc/pki/libvirt-vnc/ca-cert.pem" }
{ "#comment" = "" }
{ "vnc_tls_x509_verify" = "1" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "The default VNC password. Only 8 letters are significant for" }
{ "#comment" = "VNC passwords. This parameter is only used if the per-domain" }
{ "#comment" = "XML config does not already provide a password. To allow" }
{ "#comment" = "access without passwords, leave this commented out. An empty" }
{ "#comment" = "string will still enable passwords, but be rejected by QEMU" }
{ "#comment" = "effectively preventing any use of VNC. Obviously change this" }
{ "#comment" = "example here before you set this" }
{ "#comment" = "" }
{ "vnc_password" = "XYZ12345" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "Enable use of SASL encryption on the VNC server. This requires" }
{ "#comment" = "a VNC client which supports the SASL protocol extension." }
{ "#comment" = "Examples include vinagre, virt-viewer and virt-manager" }
{ "#comment" = "itself. UltraVNC, RealVNC, TightVNC do not support this" }
{ "#comment" = "" }
{ "#comment" = "It is necessary to configure /etc/sasl2/qemu.conf to choose" }
{ "#comment" = "the desired SASL plugin (eg, GSSPI for Kerberos)" }
{ "#comment" = "" }
{ "vnc_sasl" = "1" }
{ "#empty" }
{ "#empty" }
{ "#comment" = "The default SASL configuration file is located in /etc/sasl2/" }
{ "#comment" = "When running libvirtd unprivileged, it may be desirable to" }
{ "#comment" = "override the configs in this location. Set this parameter to" }
{ "#comment" = "point to the directory, and create a qemu.conf in that location" }
{ "#comment" = "" }
{ "vnc_sasl_dir" = "/some/directory/sasl2" }
{ "#empty" }
{ "security_driver" = "selinux" }
{ "#empty" }
{ "user" = "root" }
{ "#empty" }
{ "group" = "root" }
{ "#empty" }
{ "dynamic_ownership" = "1" }
{ "#empty" }
{ "cgroup_controllers"
    { "1" = "cpu" }
    { "2" = "devices" }
}
{ "#empty" }
{ "cgroup_device_acl"
    { "1" = "/dev/null" }
    { "2" = "/dev/full" }
    { "3" = "/dev/zero" }
}
{ "#empty" }
{ "save_image_format" = "gzip" }
{ "#empty" }
{ "dump_image_format" = "gzip" }
{ "#empty" }
{ "auto_dump_path" = "/var/lib/libvirt/qemu/dump" }
{ "#empty" }
{ "hugetlbfs_mount" = "/dev/hugepages" }
{ "#empty" }
{ "set_process_name" = "1" }
{ "#empty" }
{ "relaxed_acs_check" = "1" }
{ "#empty" }
{ "vnc_allow_host_audio" = "1" }
{ "#empty" }
{ "clear_emulator_capabilities" = "0" }
{ "#empty" }
{ "allow_disk_format_probing" = "1" }
{ "#empty" }
{ "vnc_auto_unix_socket" = "1" }
{ "#empty" }
{ "max_processes" = "12345" }
{ "#empty" }
{ "max_files" = "67890" }
{ "#empty" }
{ "lock_manager" = "fcntl" }
{ "#empty" }
{ "keepalive_interval" = "1" }
{ "keepalive_count" = "42" }
