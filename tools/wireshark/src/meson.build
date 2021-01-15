subdir('libvirt')

shared_library(
  'virt',
  [
    'packet-libvirt.c',
    'plugin.c',
    wireshark_protocol,
  ],
  dependencies: [
    wireshark_dep,
    xdr_dep,
    tools_dep,
  ],
  link_args: [
    coverage_flags
  ],
  install: true,
  install_dir: wireshark_plugindir,
)
