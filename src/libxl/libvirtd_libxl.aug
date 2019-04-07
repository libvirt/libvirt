(* /etc/libvirt/libxl.conf *)

module Libvirtd_libxl =
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
   let autoballoon_entry = bool_entry "autoballoon"
   let lock_entry = str_entry "lock_manager"
   let keepalive_interval_entry = int_entry "keepalive_interval"
   let keepalive_count_entry = int_entry "keepalive_count"
   let nested_hvm_entry = bool_entry "nested_hvm"

   (* Each entry in the config is one of the following ... *)
   let entry = autoballoon_entry
             | lock_entry
             | keepalive_interval_entry
             | keepalive_count_entry
             | nested_hvm_entry

   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/libxl.conf"
              . Util.stdexcl

   let xfm = transform lns filter
