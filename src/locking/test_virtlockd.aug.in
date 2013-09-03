module Test_virtlockd =
  let conf = "log_level = 3
log_filters=\"3:remote 4:event\"
log_outputs=\"3:syslog:libvirtd\"
log_buffer_size = 64
"

   test Virtlockd.lns get conf =
        { "log_level" = "3" }
        { "log_filters" = "3:remote 4:event" }
        { "log_outputs" = "3:syslog:libvirtd" }
        { "log_buffer_size" = "64" }
