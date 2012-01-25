(* /etc/libvirt/qemu.conf *)

module Libvirtd_qemu =
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
   let int_entry       (kw:string) = [ key kw . value_sep . int_val ]
   let str_array_entry (kw:string) = [ key kw . value_sep . str_array_val ]


   (* Config entry grouped by function - same order as example config *)
   let vnc_entry = str_entry "vnc_listen"
                 | bool_entry "vnc_auto_unix_socket"
                 | bool_entry "vnc_tls"
                 | str_entry "vnc_tls_x509_cert_dir"
                 | bool_entry "vnc_tls_x509_verify"
                 | str_entry "vnc_password"
                 | bool_entry "vnc_sasl"
                 | str_entry "vnc_sasl_dir"
                 | str_entry "security_driver"
                 | bool_entry "security_default_confined"
                 | bool_entry "security_require_confined"
                 | str_entry "user"
                 | str_entry "group"
                 | bool_entry "dynamic_ownership"
                 | str_array_entry "cgroup_controllers"
                 | str_array_entry "cgroup_device_acl"
                 | str_entry "save_image_format"
                 | str_entry "dump_image_format"
                 | str_entry "auto_dump_path"
                 | bool_entry "auto_dump_bypass_cache"
                 | bool_entry "auto_start_bypass_cache"
                 | str_entry "hugetlbfs_mount"
                 | bool_entry "relaxed_acs_check"
                 | bool_entry "vnc_allow_host_audio"
                 | bool_entry "clear_emulator_capabilities"
                 | bool_entry "allow_disk_format_probing"
                 | bool_entry "set_process_name"
                 | int_entry "max_processes"
                 | int_entry "max_files"
                 | str_entry "lock_manager"
                 | int_entry "max_queued"
                 | int_entry "keepalive_interval"
                 | int_entry "keepalive_count"

   (* Each enty in the config is one of the following three ... *)
   let entry = vnc_entry
   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/qemu.conf"
              . Util.stdexcl

   let xfm = transform lns filter
