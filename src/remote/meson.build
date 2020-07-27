remote_driver_sources = [
  'remote_driver.c',
]

remote_driver_generated = []

foreach name : [ 'remote', 'qemu', 'lxc' ]
  client_bodies_h = '@0@_client_bodies.h'.format(name)
  protocol_c = '@0@_protocol.c'.format(name)
  protocol_h = '@0@_protocol.h'.format(name)
  protocol_x = '@0@_protocol.x'.format(name)

  remote_driver_generated += custom_target(
    client_bodies_h,
    input: protocol_x,
    output: client_bodies_h,
    command: [
      gendispatch_prog, '--mode=client', name, name.to_upper(), '@INPUT@',
    ],
    capture: true,
  )

  remote_driver_generated += custom_target(
    protocol_h,
    input: protocol_x,
    output: protocol_h,
    command: [
      genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
    ],
  )

  remote_driver_generated += custom_target(
    protocol_c,
    input: protocol_x,
    output: protocol_c,
    command: [
      genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
    ],
  )
endforeach

if conf.has('WITH_REMOTE')
  remote_driver_lib = static_library(
    'virt_remote_driver',
    [
      remote_driver_sources,
      remote_driver_generated,
    ],
    dependencies: [
      rpc_dep,
      sasl_dep,
      src_dep,
      xdr_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  libvirt_libs += remote_driver_lib
endif

if conf.has('WITH_REMOTE')
  used_sym_files += 'libvirt_remote.syms'
else
  sym_files += 'libvirt_remote.syms'
endif

remote_inc_dir = include_directories('.')
