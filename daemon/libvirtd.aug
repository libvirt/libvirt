(* /etc/libvirt/libvirtd.conf *)

module Libvirtd =
   autoload xfm

   let eol   = del /[ \t]*\n/ "\n"
   let value_sep   = del /[ \t]*=[ \t]*/  " = "
   let indent = del /[ \t]*/ ""

   let array_sep  = del /,[ \t\n]*/ ", "
   let array_start = del /\[[ \t\n]*/ "[ "
   let array_end = del /\]/ "]"

   let str_val = del /\"/ "\"" . store /[^\"]*/ . del /\"/ "\""
   let bool_val = store /0|1/
   let int_val = store /[0-9]+/
   let str_array_element = [ seq "el" . str_val ] . del /[ \t\n]*/ ""
   let str_array_val = counter "el" . array_start . ( str_array_element . ( array_sep . str_array_element ) * ) ? . array_end

   let str_entry       (kw:string) = [ key kw . value_sep . str_val ]
   let bool_entry      (kw:string) = [ key kw . value_sep . bool_val ]
   let int_entry      (kw:string) = [ key kw . value_sep . int_val ]
   let str_array_entry (kw:string) = [ key kw . value_sep . str_array_val ]


   (* Config entry grouped by function - same order as example config *)
   let network_entry = bool_entry "listen_tls"
                     | bool_entry "listen_tcp"
                     | str_entry "tls_port"
                     | str_entry "tcp_port"
                     | str_entry "listen_addr"
                     | bool_entry "mdns_adv"
                     | str_entry "mdns_name"

   let sock_acl_entry = str_entry "unix_sock_group"
                      | str_entry "unix_sock_ro_perms"
                      | str_entry "unix_sock_rw_perms"
                      | str_entry "unix_sock_dir"

   let authentication_entry = str_entry "auth_unix_ro"
                            | str_entry "auth_unix_rw"
                            | str_entry "auth_tcp"
                            | str_entry "auth_tls"

   let certificate_entry = str_entry "key_file"
                         | str_entry "cert_file"
                         | str_entry "ca_file"
                         | str_entry "crl_file"

   let authorization_entry = bool_entry "tls_no_verify_certificate"
                           | bool_entry "tls_no_sanity_certificate"
                           | str_array_entry "tls_allowed_dn_list"
                           | str_array_entry "sasl_allowed_username_list"
                           | str_array_entry "access_drivers"

   let processing_entry = int_entry "min_workers"
                        | int_entry "max_workers"
                        | int_entry "max_clients"
                        | int_entry "max_queued_clients"
                        | int_entry "max_anonymous_clients"
                        | int_entry "max_requests"
                        | int_entry "max_client_requests"
                        | int_entry "prio_workers"

   let logging_entry = int_entry "log_level"
                     | str_entry "log_filters"
                     | str_entry "log_outputs"
                     | int_entry "log_buffer_size"

   let auditing_entry = int_entry "audit_level"
                      | bool_entry "audit_logging"

   let keepalive_entry = int_entry "keepalive_interval"
                       | int_entry "keepalive_count"
                       | bool_entry "keepalive_required"

   let misc_entry = str_entry "host_uuid"

   (* Each enty in the config is one of the following three ... *)
   let entry = network_entry
             | sock_acl_entry
             | authentication_entry
             | certificate_entry
             | authorization_entry
             | processing_entry
             | logging_entry
             | auditing_entry
             | keepalive_entry
             | misc_entry
   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/libvirtd.conf"
              . Util.stdexcl

   let xfm = transform lns filter
