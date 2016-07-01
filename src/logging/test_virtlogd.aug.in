module Test_virtlogd =
  let conf = "log_level = 3
log_filters=\"3:remote 4:event\"
log_outputs=\"3:syslog:virtlogd\"
max_size = 131072
max_backups = 3
"

   test Virtlogd.lns get conf =
        { "log_level" = "3" }
        { "log_filters" = "3:remote 4:event" }
        { "log_outputs" = "3:syslog:virtlogd" }
        { "max_size" = "131072" }
        { "max_backups" = "3" }
