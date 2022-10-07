wireshark_protocol = custom_target(
  'protocol.h',
  input: [
    meson.project_source_root() / 'src' / 'remote' / 'remote_protocol.x',
    meson.project_source_root() / 'src' / 'remote' / 'qemu_protocol.x',
    meson.project_source_root() / 'src' / 'remote' / 'lxc_protocol.x',
    meson.project_source_root() / 'src' / 'rpc' / 'virkeepaliveprotocol.x',
  ],
  output: [
    'protocol.h',
    'remote.h',
    'qemu.h',
    'lxc.h',
    'keepalive.h',
  ],
  command: [
    genxdrstup_prog, meson.project_version(),
    meson.current_build_dir(), '@INPUT@',
  ],
)
