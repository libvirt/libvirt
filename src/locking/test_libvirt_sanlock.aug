module Test_libvirt_sanlock =

   let conf = "require_lease_for_disks = 1
"

   test Libvirt_sanlock.lns get conf =
{ "require_lease_for_disks" = "1" }
