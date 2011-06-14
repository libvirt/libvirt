module Test_libvirt_sanlock =

   let conf = "auto_disk_leases = 1
disk_lease_dir = \"/var/lib/libvirt/sanlock\"
host_id = 1
require_lease_for_disks = 1
"

   test Libvirt_sanlock.lns get conf =
{ "auto_disk_leases" = "1" }
{ "disk_lease_dir" = "/var/lib/libvirt/sanlock" }
{ "host_id" = "1" }
{ "require_lease_for_disks" = "1" }
