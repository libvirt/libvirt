(* /etc/libvirt/lxc.conf *)

module Libvirtd_lxc =
   autoload xfm

   let eol   = del /[ \t]*\n/ "\n"
   let value_sep   = del /[ \t]*=[ \t]*/  " = "
   let indent = del /[ \t]*/ ""

   let bool_val = store /0|1/

   let bool_entry      (kw:string) = [ key kw . value_sep . bool_val ]


   (* Config entry grouped by function - same order as example config *)
   let log_entry = bool_entry "log_with_libvirtd"

   (* Each enty in the config is one of the following three ... *)
   let entry = log_entry
   let comment = [ label "#comment" . del /#[ \t]*/ "# " .  store /([^ \t\n][^\n]*)?/ . del /\n/ "\n" ]
   let empty = [ label "#empty" . eol ]

   let record = indent . entry . eol

   let lns = ( record | comment | empty ) *

   let filter = incl "/etc/libvirt/lxc.conf"
              . Util.stdexcl

   let xfm = transform lns filter
