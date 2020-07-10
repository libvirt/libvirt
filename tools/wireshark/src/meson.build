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
  install: true,
  install_dir: wireshark_plugindir,
)
