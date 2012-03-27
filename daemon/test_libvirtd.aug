module Test_libvirtd =
   let conf = "# Master libvirt daemon configuration file
#
# For further information consult http://libvirt.org/format.html


#################################################################
#
# Network connectivity controls
#

# Flag listening for secure TLS connections on the public TCP/IP port.
# NB, must pass the --listen flag to the libvirtd process for this to
# have any effect.
#
# It is necessary to setup a CA and issue server certificates before
# using this capability.
#
# This is enabled by default, uncomment this to disable it
listen_tls = 0

# Listen for unencrypted TCP connections on the public TCP/IP port.
# NB, must pass the --listen flag to the libvirtd process for this to
# have any effect.
#
# Using the TCP socket requires SASL authentication by default. Only
# SASL mechanisms which support data encryption are allowed. This is
# DIGEST_MD5 and GSSAPI (Kerberos5)
#
# This is disabled by default, uncomment this to enable it.
listen_tcp = 1



# Override the port for accepting secure TLS connections
# This can be a port number, or service name
#
tls_port = \"16514\"

# Override the port for accepting insecure TCP connections
# This can be a port number, or service name
#
tcp_port = \"16509\"


# Override the default configuration which binds to all network
# interfaces. This can be a numeric IPv4/6 address, or hostname
#
listen_addr = \"192.168.0.1\"


# Flag toggling mDNS advertizement of the libvirt service.
#
# Alternatively can disable for all services on a host by
# stopping the Avahi daemon
#
# This is disabled by default, uncomment this to enable it
mdns_adv = 1

# Override the default mDNS advertizement name. This must be
# unique on the immediate broadcast network.
#
# The default is \"Virtualization Host HOSTNAME\", where HOSTNAME
# is subsituted for the short hostname of the machine (without domain)
#
mdns_name = \"Virtualization Host Joe Demo\"


#################################################################
#
# UNIX socket access controls
#

# Set the UNIX domain socket group ownership. This can be used to
# allow a 'trusted' set of users access to management capabilities
# without becoming root.
#
# This is restricted to 'root' by default.
unix_sock_group = \"libvirt\"

# Set the UNIX socket permissions for the R/O socket. This is used
# for monitoring VM status only
#
# Default allows any user. If setting group ownership may want to
# restrict this to:
unix_sock_ro_perms = \"0777\"

# Set the UNIX socket permissions for the R/W socket. This is used
# for full management of VMs
#
# Default allows only root. If PolicyKit is enabled on the socket,
# the default will change to allow everyone (eg, 0777)
#
# If not using PolicyKit and setting group ownership for access
# control then you may want to relax this to:
unix_sock_rw_perms = \"0770\"



#################################################################
#
# Authentication.
#
#  - none: do not perform auth checks. If you can connect to the
#          socket you are allowed. This is suitable if there are
#          restrictions on connecting to the socket (eg, UNIX
#          socket permissions), or if there is a lower layer in
#          the network providing auth (eg, TLS/x509 certificates)
#
#  - sasl: use SASL infrastructure. The actual auth scheme is then
#          controlled from /etc/sasl2/libvirt.conf. For the TCP
#          socket only GSSAPI & DIGEST-MD5 mechanisms will be used.
#          For non-TCP or TLS sockets,  any scheme is allowed.
#
#  - polkit: use PolicyKit to authenticate. This is only suitable
#            for use on the UNIX sockets. The default policy will
#            require a user to supply their own password to gain
#            full read/write access (aka sudo like), while anyone
#            is allowed read/only access.
#
# Set an authentication scheme for UNIX read-only sockets
# By default socket permissions allow anyone to connect
#
# To restrict monitoring of domains you may wish to enable
# an authentication mechanism here
auth_unix_ro = \"none\"

# Set an authentication scheme for UNIX read-write sockets
# By default socket permissions only allow root. If PolicyKit
# support was compiled into libvirt, the default will be to
# use 'polkit' auth.
#
# If the unix_sock_rw_perms are changed you may wish to enable
# an authentication mechanism here
auth_unix_rw = \"none\"

# Change the authentication scheme for TCP sockets.
#
# If you don't enable SASL, then all TCP traffic is cleartext.
# Don't do this outside of a dev/test scenario. For real world
# use, always enable SASL and use the GSSAPI or DIGEST-MD5
# mechanism in /etc/sasl2/libvirt.conf
auth_tcp = \"sasl\"

# Change the authentication scheme for TLS sockets.
#
# TLS sockets already have encryption provided by the TLS
# layer, and limited authentication is done by certificates
#
# It is possible to make use of any SASL authentication
# mechanism as well, by using 'sasl' for this option
auth_tls = \"none\"



#################################################################
#
# TLS x509 certificate configuration
#


# Override the default server key file path
#
key_file = \"/etc/pki/libvirt/private/serverkey.pem\"

# Override the default server certificate file path
#
cert_file = \"/etc/pki/libvirt/servercert.pem\"

# Override the default CA certificate path
#
ca_file = \"/etc/pki/CA/cacert.pem\"

# Specify a certificate revocation list.
#
# Defaults to not using a CRL, uncomment to enable it
crl_file = \"/etc/pki/CA/crl.pem\"



#################################################################
#
# Authorization controls
#


# Flag to disable verification of client certificates
#
# Client certificate verification is the primary authentication mechanism.
# Any client which does not present a certificate signed by the CA
# will be rejected.
#
# Default is to always verify. Uncommenting this will disable
# verification - make sure an IP whitelist is set
tls_no_verify_certificate = 1
tls_no_sanity_certificate = 1


# A whitelist of allowed x509  Distinguished Names
# This list may contain wildcards such as
#
#    \"C=GB,ST=London,L=London,O=Red Hat,CN=*\"
#
# See the POSIX fnmatch function for the format of the wildcards.
#
# NB If this is an empty list, no client can connect, so comment out
# entirely rather than using empty list to disable these checks
#
# By default, no DN's are checked
   tls_allowed_dn_list = [\"DN1\", \"DN2\"]


# A whitelist of allowed SASL usernames. The format for usernames
# depends on the SASL authentication mechanism. Kerberos usernames
# look like username@REALM
#
# This list may contain wildcards such as
#
#    \"*@EXAMPLE.COM\"
#
# See the POSIX fnmatch function for the format of the wildcards.
#
# NB If this is an empty list, no client can connect, so comment out
# entirely rather than using empty list to disable these checks
#
# By default, no Username's are checked
sasl_allowed_username_list = [
  \"joe@EXAMPLE.COM\",
  \"fred@EXAMPLE.COM\"
]


#################################################################
#
# Processing controls
#

# The maximum number of concurrent client connections to allow
# over all sockets combined.
max_clients = 20


# The minimum limit sets the number of workers to start up
# initially. If the number of active clients exceeds this,
# then more threads are spawned, upto max_workers limit.
# Typically you'd want max_workers to equal maximum number
# of clients allowed
min_workers = 5
max_workers = 20

# Total global limit on concurrent RPC calls. Should be
# at least as large as max_workers. Beyond this, RPC requests
# will be read into memory and queued. This directly impact
# memory usage, currently each request requires 256 KB of
# memory. So by default upto 5 MB of memory is used
max_requests = 20

# Limit on concurrent requests from a single client
# connection. To avoid one client monopolizing the server
# this should be a small fraction of the global max_requests
# and max_workers parameter
max_client_requests = 5

# Logging level:
log_level = 4

# Logging outputs:
log_outputs=\"4:stderr\"

# Logging filters:
log_filters=\"a\"

# Auditing:
audit_level = 2
"

   test Libvirtd.lns get conf =
        { "#comment" = "Master libvirt daemon configuration file" }
        { "#comment" = "" }
        { "#comment" = "For further information consult http://libvirt.org/format.html" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################" }
        { "#comment" = "" }
        { "#comment" = "Network connectivity controls" }
        { "#comment" = "" }
        { "#empty" }
        { "#comment" = "Flag listening for secure TLS connections on the public TCP/IP port." }
        { "#comment" = "NB, must pass the --listen flag to the libvirtd process for this to" }
        { "#comment" = "have any effect." }
        { "#comment" = "" }
        { "#comment" = "It is necessary to setup a CA and issue server certificates before" }
        { "#comment" = "using this capability." }
        { "#comment" = "" }
        { "#comment" = "This is enabled by default, uncomment this to disable it" }
        { "listen_tls" = "0" }
        { "#empty" }
        { "#comment" = "Listen for unencrypted TCP connections on the public TCP/IP port." }
        { "#comment" = "NB, must pass the --listen flag to the libvirtd process for this to" }
        { "#comment" = "have any effect." }
        { "#comment" = "" }
        { "#comment" = "Using the TCP socket requires SASL authentication by default. Only" }
        { "#comment" = "SASL mechanisms which support data encryption are allowed. This is" }
        { "#comment" = "DIGEST_MD5 and GSSAPI (Kerberos5)" }
        { "#comment" = "" }
        { "#comment" = "This is disabled by default, uncomment this to enable it." }
        { "listen_tcp" = "1" }
        { "#empty" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "Override the port for accepting secure TLS connections" }
        { "#comment" = "This can be a port number, or service name" }
        { "#comment" = "" }
        { "tls_port" = "16514" }
        { "#empty" }
        { "#comment" = "Override the port for accepting insecure TCP connections" }
        { "#comment" = "This can be a port number, or service name" }
        { "#comment" = "" }
        { "tcp_port" = "16509" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "Override the default configuration which binds to all network" }
        { "#comment" = "interfaces. This can be a numeric IPv4/6 address, or hostname" }
        { "#comment" = "" }
        { "listen_addr" = "192.168.0.1" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "Flag toggling mDNS advertizement of the libvirt service." }
        { "#comment" = "" }
        { "#comment" = "Alternatively can disable for all services on a host by" }
        { "#comment" = "stopping the Avahi daemon" }
        { "#comment" = "" }
        { "#comment" = "This is disabled by default, uncomment this to enable it" }
        { "mdns_adv" = "1" }
        { "#empty" }
        { "#comment" = "Override the default mDNS advertizement name. This must be" }
        { "#comment" = "unique on the immediate broadcast network." }
        { "#comment" = "" }
        { "#comment" = "The default is \"Virtualization Host HOSTNAME\", where HOSTNAME" }
        { "#comment" = "is subsituted for the short hostname of the machine (without domain)" }
        { "#comment" = "" }
        { "mdns_name" = "Virtualization Host Joe Demo" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################" }
        { "#comment" = "" }
        { "#comment" = "UNIX socket access controls" }
        { "#comment" = "" }
        { "#empty" }
        { "#comment" = "Set the UNIX domain socket group ownership. This can be used to" }
        { "#comment" = "allow a 'trusted' set of users access to management capabilities" }
        { "#comment" = "without becoming root." }
        { "#comment" = "" }
        { "#comment" = "This is restricted to 'root' by default." }
        { "unix_sock_group" = "libvirt" }
        { "#empty" }
        { "#comment" = "Set the UNIX socket permissions for the R/O socket. This is used" }
        { "#comment" = "for monitoring VM status only" }
        { "#comment" = "" }
        { "#comment" = "Default allows any user. If setting group ownership may want to" }
        { "#comment" = "restrict this to:" }
        { "unix_sock_ro_perms" = "0777" }
        { "#empty" }
        { "#comment" = "Set the UNIX socket permissions for the R/W socket. This is used" }
        { "#comment" = "for full management of VMs" }
        { "#comment" = "" }
        { "#comment" = "Default allows only root. If PolicyKit is enabled on the socket," }
        { "#comment" = "the default will change to allow everyone (eg, 0777)" }
        { "#comment" = "" }
        { "#comment" = "If not using PolicyKit and setting group ownership for access" }
        { "#comment" = "control then you may want to relax this to:" }
        { "unix_sock_rw_perms" = "0770" }
        { "#empty" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################" }
        { "#comment" = "" }
        { "#comment" = "Authentication." }
        { "#comment" = "" }
        { "#comment" = "- none: do not perform auth checks. If you can connect to the" }
        { "#comment" = "socket you are allowed. This is suitable if there are" }
        { "#comment" = "restrictions on connecting to the socket (eg, UNIX" }
        { "#comment" = "socket permissions), or if there is a lower layer in" }
        { "#comment" = "the network providing auth (eg, TLS/x509 certificates)" }
        { "#comment" = "" }
        { "#comment" = "- sasl: use SASL infrastructure. The actual auth scheme is then" }
        { "#comment" = "controlled from /etc/sasl2/libvirt.conf. For the TCP" }
        { "#comment" = "socket only GSSAPI & DIGEST-MD5 mechanisms will be used." }
        { "#comment" = "For non-TCP or TLS sockets,  any scheme is allowed." }
        { "#comment" = "" }
        { "#comment" = "- polkit: use PolicyKit to authenticate. This is only suitable" }
        { "#comment" = "for use on the UNIX sockets. The default policy will" }
        { "#comment" = "require a user to supply their own password to gain" }
        { "#comment" = "full read/write access (aka sudo like), while anyone" }
        { "#comment" = "is allowed read/only access." }
        { "#comment" = "" }
        { "#comment" = "Set an authentication scheme for UNIX read-only sockets" }
        { "#comment" = "By default socket permissions allow anyone to connect" }
        { "#comment" = "" }
        { "#comment" = "To restrict monitoring of domains you may wish to enable" }
        { "#comment" = "an authentication mechanism here" }
        { "auth_unix_ro" = "none" }
        { "#empty" }
        { "#comment" = "Set an authentication scheme for UNIX read-write sockets" }
        { "#comment" = "By default socket permissions only allow root. If PolicyKit" }
        { "#comment" = "support was compiled into libvirt, the default will be to" }
        { "#comment" = "use 'polkit' auth." }
        { "#comment" = "" }
        { "#comment" = "If the unix_sock_rw_perms are changed you may wish to enable" }
        { "#comment" = "an authentication mechanism here" }
        { "auth_unix_rw" = "none" }
        { "#empty" }
        { "#comment" = "Change the authentication scheme for TCP sockets." }
        { "#comment" = "" }
        { "#comment" = "If you don't enable SASL, then all TCP traffic is cleartext." }
        { "#comment" = "Don't do this outside of a dev/test scenario. For real world" }
        { "#comment" = "use, always enable SASL and use the GSSAPI or DIGEST-MD5" }
        { "#comment" = "mechanism in /etc/sasl2/libvirt.conf" }
        { "auth_tcp" = "sasl" }
        { "#empty" }
        { "#comment" = "Change the authentication scheme for TLS sockets." }
        { "#comment" = "" }
        { "#comment" = "TLS sockets already have encryption provided by the TLS" }
        { "#comment" = "layer, and limited authentication is done by certificates" }
        { "#comment" = "" }
        { "#comment" = "It is possible to make use of any SASL authentication" }
        { "#comment" = "mechanism as well, by using 'sasl' for this option" }
        { "auth_tls" = "none" }
        { "#empty" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################" }
        { "#comment" = "" }
        { "#comment" = "TLS x509 certificate configuration" }
        { "#comment" = "" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "Override the default server key file path" }
        { "#comment" = "" }
        { "key_file" = "/etc/pki/libvirt/private/serverkey.pem" }
        { "#empty" }
        { "#comment" = "Override the default server certificate file path" }
        { "#comment" = "" }
        { "cert_file" = "/etc/pki/libvirt/servercert.pem" }
        { "#empty" }
        { "#comment" = "Override the default CA certificate path" }
        { "#comment" = "" }
        { "ca_file" = "/etc/pki/CA/cacert.pem" }
        { "#empty" }
        { "#comment" = "Specify a certificate revocation list." }
        { "#comment" = "" }
        { "#comment" = "Defaults to not using a CRL, uncomment to enable it" }
        { "crl_file" = "/etc/pki/CA/crl.pem" }
        { "#empty" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################" }
        { "#comment" = "" }
        { "#comment" = "Authorization controls" }
        { "#comment" = "" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "Flag to disable verification of client certificates" }
        { "#comment" = "" }
        { "#comment" = "Client certificate verification is the primary authentication mechanism." }
        { "#comment" = "Any client which does not present a certificate signed by the CA" }
        { "#comment" = "will be rejected." }
        { "#comment" = "" }
        { "#comment" = "Default is to always verify. Uncommenting this will disable" }
        { "#comment" = "verification - make sure an IP whitelist is set" }
        { "tls_no_verify_certificate" = "1" }
        { "tls_no_sanity_certificate" = "1" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "A whitelist of allowed x509  Distinguished Names" }
        { "#comment" = "This list may contain wildcards such as" }
        { "#comment" = "" }
        { "#comment" = "\"C=GB,ST=London,L=London,O=Red Hat,CN=*\"" }
        { "#comment" = "" }
        { "#comment" = "See the POSIX fnmatch function for the format of the wildcards." }
        { "#comment" = "" }
        { "#comment" = "NB If this is an empty list, no client can connect, so comment out" }
        { "#comment" = "entirely rather than using empty list to disable these checks" }
        { "#comment" = "" }
        { "#comment" = "By default, no DN's are checked" }
        { "tls_allowed_dn_list"
             { "1" = "DN1"}
             { "2" = "DN2"}
        }
        { "#empty" }
        { "#empty" }
        { "#comment" = "A whitelist of allowed SASL usernames. The format for usernames" }
        { "#comment" = "depends on the SASL authentication mechanism. Kerberos usernames" }
        { "#comment" = "look like username@REALM" }
        { "#comment" = "" }
        { "#comment" = "This list may contain wildcards such as" }
        { "#comment" = "" }
        { "#comment" = "\"*@EXAMPLE.COM\"" }
        { "#comment" = "" }
        { "#comment" = "See the POSIX fnmatch function for the format of the wildcards." }
        { "#comment" = "" }
        { "#comment" = "NB If this is an empty list, no client can connect, so comment out" }
        { "#comment" = "entirely rather than using empty list to disable these checks" }
        { "#comment" = "" }
        { "#comment" = "By default, no Username's are checked" }
        { "sasl_allowed_username_list"
             { "1" = "joe@EXAMPLE.COM" }
             { "2" = "fred@EXAMPLE.COM" }
        }
        { "#empty" }
        { "#empty" }
        { "#comment" = "################################################################"}
        { "#comment" = ""}
        { "#comment" = "Processing controls"}
        { "#comment" = ""}
        { "#empty" }
        { "#comment" = "The maximum number of concurrent client connections to allow"}
        { "#comment" = "over all sockets combined."}
        { "max_clients" = "20" }
        { "#empty" }
        { "#empty" }
        { "#comment" = "The minimum limit sets the number of workers to start up"}
        { "#comment" = "initially. If the number of active clients exceeds this,"}
        { "#comment" = "then more threads are spawned, upto max_workers limit."}
        { "#comment" = "Typically you'd want max_workers to equal maximum number"}
        { "#comment" = "of clients allowed"}
        { "min_workers" = "5" }
        { "max_workers" = "20" }
	{ "#empty" }
        { "#comment" = "Total global limit on concurrent RPC calls. Should be" }
        { "#comment" = "at least as large as max_workers. Beyond this, RPC requests" }
        { "#comment" = "will be read into memory and queued. This directly impact" }
        { "#comment" = "memory usage, currently each request requires 256 KB of" }
        { "#comment" = "memory. So by default upto 5 MB of memory is used" }
        { "max_requests" = "20" }
	{ "#empty" }
        { "#comment" = "Limit on concurrent requests from a single client" }
        { "#comment" = "connection. To avoid one client monopolizing the server" }
        { "#comment" = "this should be a small fraction of the global max_requests" }
        { "#comment" = "and max_workers parameter" }
        { "max_client_requests" = "5" }
	{ "#empty" }
        { "#comment" = "Logging level:" }
        { "log_level" = "4" }
	{ "#empty" }
        { "#comment" = "Logging outputs:" }
        { "log_outputs" = "4:stderr" }
	{ "#empty" }
        { "#comment" = "Logging filters:" }
        { "log_filters" = "a" }
	{ "#empty" }
        { "#comment" = "Auditing:" }
        { "audit_level" = "2" }
