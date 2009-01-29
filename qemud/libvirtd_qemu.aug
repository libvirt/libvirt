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
   let str_array_element = [ seq "el" . str_val ] . del /[ \t\n]*/ ""
   let str_array_val = counter "el" . array_start . ( str_array_element . ( array_sep . str_array_element ) * ) ? . array_end

   let str_entry       (kw:string) = [ key kw . value_sep . str_val ]
   let bool_entry      (kw:string) = [ key kw . value_sep . bool_val ]
   let str_array_entry (kw:string) = [ key kw . value_sep . str_array_val ]


   (* Config entry grouped by function - same order as example config *)
   let vnc_entry = str_entry "vnc_listen"
                 | bool_entry "vnc_tls"
                 | str_entry "vnc_tls_x509_cert_dir"
                 | bool_entry "vnc_tls_x509_verify"
                 | str_entry "vnc_password"

   (* Each enty in the config is one of the following three ... *)
   let entry = vnc_entry
   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/qemu.conf"
              . Util.stdexcl

   let xfm = transform lns filter

