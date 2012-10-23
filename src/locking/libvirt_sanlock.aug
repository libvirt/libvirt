(* /etc/libvirt/qemu-sanlock.conf *)

module Libvirt_sanlock =
   autoload xfm

   let eol   = del /[ \t]*\n/ "\n"
   let value_sep   = del /[ \t]*=[ \t]*/  " = "
   let indent = del /[ \t]*/ ""

   let str_val = del /\"/ "\"" . store /[^\"]*/ . del /\"/ "\""
   let bool_val = store /0|1/
   let int_val = store /[0-9]+/

   let str_entry       (kw:string) = [ key kw . value_sep . str_val ]
   let bool_entry      (kw:string) = [ key kw . value_sep . bool_val ]
   let int_entry       (kw:string) = [ key kw . value_sep . int_val ]


   (* Each enty in the config is one of the following three ... *)
   let entry = str_entry "disk_lease_dir"
             | bool_entry "auto_disk_leases"
             | int_entry "host_id"
             | bool_entry "require_lease_for_disks"
             | bool_entry "ignore_readonly_and_shared_disks"
             | str_entry "user"
             | str_entry "group"
   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/qemu-sanlock.conf"
              . Util.stdexcl

   let xfm = transform lns filter
